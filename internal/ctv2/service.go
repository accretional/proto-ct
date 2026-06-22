package ctv2

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/tls"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultUserAgent is sent when a request omits one. v1 was rate-limited by some
// operators for sending no contact UA.
const DefaultUserAgent = "proto-ct (ct@accretional.com, +https://accretional.com)"

// Service implements the v2 CTIngestionService.
type Service struct {
	pb.UnimplementedCTIngestionServiceServer

	httpClient  *http.Client
	defaultRoot string // output_root fallback when a request omits it

	mu       sync.RWMutex
	logList  *pb.CTLogList
	byLogID  map[string]*pb.CTLog // hex(log_id) -> log
	listedAt time.Time
}

// NewService returns a Service. defaultOutputRoot is used when GetLogEntries
// requests omit output_root.
func NewService(defaultOutputRoot string) *Service {
	return &Service{
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		defaultRoot: defaultOutputRoot,
		byLogID:     make(map[string]*pb.CTLog),
	}
}

// ── GetLogList ───────────────────────────────────────────────────────────────

func (s *Service) GetLogList(ctx context.Context, req *pb.GetLogListRequest) (*pb.CTLogList, error) {
	url := req.GetLogListUrl()
	if url == "" {
		url = loglist3.LogListURL
	}
	list, err := s.fetchLogList(ctx, url)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "fetch log list: %v", err)
	}
	return list, nil
}

func (s *Service) fetchLogList(ctx context.Context, url string) (*pb.CTLogList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	ll, err := loglist3.NewFromJSON(body)
	if err != nil {
		return nil, fmt.Errorf("parse log list: %w", err)
	}
	mapped := mapLogList(ll)

	s.mu.Lock()
	s.logList = mapped
	s.byLogID = make(map[string]*pb.CTLog)
	for _, op := range mapped.GetOperators() {
		for _, lg := range op.GetLogs() {
			s.byLogID[hex.EncodeToString(lg.GetLogId())] = lg
		}
	}
	s.listedAt = time.Now()
	s.mu.Unlock()
	return mapped, nil
}

// lookupLog returns the cached CTLog for a log_id, fetching the default list
// once if the cache is empty.
func (s *Service) lookupLog(ctx context.Context, logID []byte) (*pb.CTLog, error) {
	key := hex.EncodeToString(logID)
	s.mu.RLock()
	lg, ok := s.byLogID[key]
	empty := len(s.byLogID) == 0
	s.mu.RUnlock()
	if ok {
		return lg, nil
	}
	if empty {
		if _, err := s.fetchLogList(ctx, loglist3.LogListURL); err != nil {
			return nil, err
		}
		s.mu.RLock()
		lg, ok = s.byLogID[key]
		s.mu.RUnlock()
		if ok {
			return lg, nil
		}
	}
	return nil, fmt.Errorf("log_id %s not found in log list", key)
}

// ── selector resolution ──────────────────────────────────────────────────────

// resolveSelector fills monitoring_url / protocol / public_key / log_id from the
// cached log list when only log_id is supplied; otherwise validates the explicit
// fields. Returns a fully-populated copy.
func (s *Service) resolveSelector(ctx context.Context, sel *pb.LogSelector) (*pb.LogSelector, error) {
	if sel == nil {
		return nil, status.Error(codes.InvalidArgument, "log selector required")
	}
	out := &pb.LogSelector{
		LogId:         sel.GetLogId(),
		MonitoringUrl: sel.GetMonitoringUrl(),
		Protocol:      sel.GetProtocol(),
		PublicKey:     sel.GetPublicKey(),
	}
	if out.MonitoringUrl != "" && out.Protocol != pb.LogProtocol_LOG_PROTOCOL_UNSPECIFIED {
		return out, nil
	}
	if len(out.LogId) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"selector needs either (monitoring_url + protocol) or log_id")
	}
	lg, err := s.lookupLog(ctx, out.LogId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	out.Protocol = lg.GetProtocol()
	if len(out.PublicKey) == 0 {
		out.PublicKey = lg.GetKey()
	}
	if out.MonitoringUrl == "" {
		if lg.GetProtocol() == pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API {
			out.MonitoringUrl = lg.GetMonitoringUrl()
		} else {
			out.MonitoringUrl = lg.GetUrl()
		}
	}
	return out, nil
}

// ── GetSTH ───────────────────────────────────────────────────────────────────

func (s *Service) GetSTH(ctx context.Context, req *pb.GetSTHRequest) (*pb.STHResponse, error) {
	sel, err := s.resolveSelector(ctx, req.GetLog())
	if err != nil {
		return nil, err
	}
	return s.fetchSTH(ctx, sel)
}

// fetchSTH retrieves the current STH/checkpoint for an already-resolved selector.
func (s *Service) fetchSTH(ctx context.Context, sel *pb.LogSelector) (*pb.STHResponse, error) {
	switch sel.Protocol {
	case pb.LogProtocol_LOG_PROTOCOL_RFC6962:
		lc, err := client.New(sel.MonitoringUrl, s.httpClient, jsonclient.Options{UserAgent: DefaultUserAgent})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "rfc6962 client: %v", err)
		}
		sth, err := lc.GetSTH(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "get-sth: %v", err)
		}
		sig, _ := tls.Marshal(sth.TreeHeadSignature)
		return &pb.STHResponse{
			LogId:             sel.LogId,
			TreeSize:          int64(sth.TreeSize),
			Timestamp:         int64(sth.Timestamp),
			Sha256RootHash:    sth.SHA256RootHash[:],
			TreeHeadSignature: sig,
		}, nil
	case pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API:
		sf, err := newStaticFetcher(sel, DefaultUserAgent, 0, 0, 0)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return sf.sth(ctx, sel.LogId)
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown or unspecified log protocol")
	}
}

// ── GetLogEntries ────────────────────────────────────────────────────────────

func (s *Service) GetLogEntries(ctx context.Context, req *pb.GetLogEntriesRequest) (*pb.GetLogEntriesResponse, error) {
	if req.GetStartIndex() < 0 || req.GetEndIndex() < req.GetStartIndex() {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid range [%d, %d)", req.GetStartIndex(), req.GetEndIndex())
	}
	sel, err := s.resolveSelector(ctx, req.GetLog())
	if err != nil {
		return nil, err
	}

	ua := req.GetUserAgent()
	if ua == "" {
		ua = DefaultUserAgent
	}
	root := req.GetOutputRoot()
	if root == "" {
		root = s.defaultRoot
	}
	if root == "" {
		return nil, status.Error(codes.InvalidArgument, "output_root required (no server default configured)")
	}

	var fetcher RangeFetcher
	switch sel.Protocol {
	case pb.LogProtocol_LOG_PROTOCOL_RFC6962:
		fetcher, err = newRFC6962Fetcher(sel, ua, req.GetTargetQps(), int(req.GetPageSize()), int(req.GetFetchConcurrency()), req.GetDisableKeepAlive())
	case pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API:
		fetcher, err = newStaticFetcher(sel, ua, req.GetTargetQps(), int(req.GetFetchConcurrency()), int(req.GetPageSize()))
	case pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API_NO_CHECKPOINT:
		fetcher, err = newTileFetcher(sel, ua, req.GetTargetQps(), int(req.GetFetchConcurrency()))
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown or unspecified log protocol")
	}
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "build fetcher: %v", err)
	}

	meta := &pb.LogMeta{
		LogId:         sel.LogId,
		MonitoringUrl: sel.MonitoringUrl,
		Protocol:      sel.Protocol,
	}
	// RFC6962 carries the issuer chain inline (extra_data); we dedupe it into a
	// shared issuer store rather than repeating it per leaf. static/tile records
	// carry chain fingerprints only (certs live at the log's issuer endpoint), so
	// they never feed the store — leave it nil for them.
	w := &LocalFSWriter{Root: root}
	var issuers *issuerStore
	if sel.Protocol == pb.LogProtocol_LOG_PROTOCOL_RFC6962 {
		issuers = newIssuerStore(w)
	}
	sink := newBatchSink(w, meta, req.GetGranularity(), issuers)

	sinkFn := func(b entryBatch) error { return sink.writeBatch(ctx, b) }
	if err := fetcher.Fetch(ctx, req.GetStartIndex(), req.GetEndIndex(), sinkFn); err != nil {
		return nil, status.Errorf(codes.Internal, "fetch range: %v", err)
	}

	return &pb.GetLogEntriesResponse{
		EntriesWritten: sink.entriesWritten,
		BytesWritten:   sink.bytesWritten,
		FirstIndex:     sink.firstIndex,
		LastIndex:      sink.lastIndex,
	}, nil
}

// ── CheckCoverage ────────────────────────────────────────────────────────────

func (s *Service) CheckCoverage(ctx context.Context, req *pb.CheckCoverageRequest) (*pb.CheckCoverageResponse, error) {
	if req.GetOutputRoot() == "" {
		return nil, status.Error(codes.InvalidArgument, "output_root required")
	}
	// output_root is per-log (the caller owns the log-level prefix), so the disk
	// scan needs no log identity — just count every partition file under it.
	ranges, files, err := scanPartitionRanges(req.GetOutputRoot())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "scan %s: %v", req.GetOutputRoot(), err)
	}

	// Optionally query the live STH for tree_size/coverage. The disk-derived
	// stats don't depend on it, so an STH failure (e.g. the log rate-limiting us
	// while a mirror is running) degrades to disk-only with sth_error set, rather
	// than failing the whole call. Only this path needs the log selector.
	var treeSize int64
	var sthErr string
	if req.GetQuerySth() {
		if sel, err := s.resolveSelector(ctx, req.GetLog()); err != nil {
			sthErr = err.Error()
		} else if sth, err := s.fetchSTH(ctx, sel); err != nil {
			sthErr = err.Error()
		} else {
			treeSize = sth.GetTreeSize()
		}
	}

	stored, frontier, contiguous, gaps := summarizeRanges(ranges, treeSize)
	resp := &pb.CheckCoverageResponse{
		TreeSize:          treeSize,
		StoredEntries:     stored,
		Frontier:          frontier,
		ContiguousThrough: contiguous,
		PartitionFiles:    int64(files),
		SthError:          sthErr,
	}
	if treeSize > 0 {
		resp.CoveragePct = float64(stored) / float64(treeSize) * 100
	}
	if req.GetIncludeGaps() {
		for _, g := range gaps {
			resp.Gaps = append(resp.Gaps, &pb.IndexRange{Start: g.start, End: g.end})
		}
	}
	return resp, nil
}
