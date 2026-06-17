package ctv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"google.golang.org/protobuf/proto"
)

// logSlug derives a stable, filesystem-safe directory name for a log: the hex
// log_id when known, else a sanitized monitoring URL.
func logSlug(meta *pb.LogMeta) string {
	if len(meta.GetLogId()) > 0 {
		return hex.EncodeToString(meta.GetLogId())
	}
	u := meta.GetMonitoringUrl()
	if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
		u = parsed.Host + parsed.Path
	}
	u = strings.TrimRight(u, "/")
	repl := strings.NewReplacer("/", "_", ":", "_", " ", "_")
	slug := repl.Replace(u)
	if slug == "" {
		h := sha256.Sum256([]byte(meta.GetMonitoringUrl()))
		return hex.EncodeToString(h[:8])
	}
	return slug
}

// leafDay returns the partition sub-path (relative to the log slug) for a leaf
// timestamp at the requested granularity: "YYYY-MM-DD" or "YYYY-MM-DD/HH" (UTC).
func leafDay(tsMs int64, g pb.PartitionGranularity) string {
	t := time.UnixMilli(tsMs).UTC()
	if g == pb.PartitionGranularity_PARTITION_GRANULARITY_HOUR {
		return path.Join(t.Format("2006-01-02"), t.Format("15"))
	}
	return t.Format("2006-01-02")
}

// batchSink writes contiguous, index-ordered batches of leaves to immutable
// binary-protobuf files. Each batch is split into one file per contiguous
// same-day run, named <slug>/<day>/<firstIdx>-<lastIdx>.binpb. Because the
// fetcher hands it disjoint batches of consecutive indices, every file covers a
// disjoint contiguous index range and a re-run of the same (log, range, batch
// size, granularity) produces byte-identical files (deterministic marshal).
// Safe for concurrent callers.
type batchSink struct {
	w           Writer
	meta        *pb.LogMeta
	slug        string
	gran        pb.PartitionGranularity
	marshalOpts proto.MarshalOptions

	mu             sync.Mutex
	entriesWritten int64
	bytesWritten   int64
	firstIndex     int64 // overall min, -1 until first write
	lastIndex      int64 // overall max, -1 until first write
}

func newBatchSink(w Writer, meta *pb.LogMeta, gran pb.PartitionGranularity) *batchSink {
	return &batchSink{
		w:           w,
		meta:        meta,
		slug:        logSlug(meta),
		gran:        gran,
		marshalOpts: proto.MarshalOptions{Deterministic: true},
		firstIndex:  -1,
		lastIndex:   -1,
	}
}

// writeBatch persists one contiguous, index-ordered batch, splitting it into a
// file per contiguous same-day run.
func (s *batchSink) writeBatch(ctx context.Context, entries []*pb.RawLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	runStart := 0
	curDay := leafDay(entries[0].GetTimestampMs(), s.gran)
	for i := 1; i < len(entries); i++ {
		d := leafDay(entries[i].GetTimestampMs(), s.gran)
		if d != curDay {
			if err := s.writeRun(ctx, curDay, entries[runStart:i]); err != nil {
				return err
			}
			runStart = i
			curDay = d
		}
	}
	return s.writeRun(ctx, curDay, entries[runStart:])
}

func (s *batchSink) writeRun(ctx context.Context, day string, run []*pb.RawLogEntry) error {
	if len(run) == 0 {
		return nil
	}
	first := run[0].GetIndex()
	last := run[len(run)-1].GetIndex()
	batch := &pb.RawLogEntryBatch{Log: s.meta, Entries: run}
	data, err := s.marshalOpts.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch %s [%d,%d]: %w", day, first, last, err)
	}
	relPath := path.Join(s.slug, day, encodeBase36(first)+"-"+encodeBase36(last)+".binpb")
	if err := s.w.Put(ctx, relPath, data); err != nil {
		return err
	}

	s.mu.Lock()
	s.entriesWritten += int64(len(run))
	s.bytesWritten += int64(len(data))
	if s.firstIndex < 0 || first < s.firstIndex {
		s.firstIndex = first
	}
	if last > s.lastIndex {
		s.lastIndex = last
	}
	s.mu.Unlock()
	return nil
}
