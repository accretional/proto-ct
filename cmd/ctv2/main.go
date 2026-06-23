// Command ctv2 is a thin client for the v2 raw-leaf archiver. It is the unit a
// cloud orchestrator launches per (log, range): it dials a ctv2-server and calls
// one RPC.
//
// Usage:
//
//	ctv2 -mode list
//	ctv2 -mode sth   -log-id <hex>
//	ctv2 -mode fetch -log-id <hex> -start 0 -end 100000 -out data/v2
//	ctv2 -mode fetch -url https://log.example/  -protocol rfc6962 -start 0 -end 1000
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	addr        = flag.String("addr", "localhost:50052", "ctv2-server address")
	mode        = flag.String("mode", "fetch", "list | sth | fetch")
	logIDHex    = flag.String("log-id", "", "target log id, hex (resolved via the server's log list)")
	url         = flag.String("url", "", "explicit monitoring/base URL (with -protocol)")
	protocol    = flag.String("protocol", "", "rfc6962 | static (required with -url)")
	pubKeyB64   = flag.String("pubkey", "", "base64 DER SPKI public key (static logs; else taken from log list)")
	start       = flag.Int64("start", 0, "start index (inclusive)")
	end         = flag.Int64("end", 0, "end index (exclusive)")
	out         = flag.String("out", "", "output root (default: server's)")
	qps         = flag.Float64("qps", 0, "target QPS (0 = unlimited)")
	concurrency = flag.Int("concurrency", 0, "fetch concurrency (static path)")
	pageSize    = flag.Int("page-size", 0, "get-entries page size hint (rfc6962)")
	granularity = flag.String("granularity", "day", "partition granularity: day | hour")
	noKeepAlive = flag.Bool("no-keepalive", false, "close each HTTP connection (no keep-alive); needed for DigiCert (rfc6962)")
	compress    = flag.String("compress", "none", "compress written files: none | gzip")
	dryRun      = flag.Bool("dry-run", false, "resolve-issuers: report missing issuers without fetching")
	index       = flag.Int64("index", -1, "verify: entry index to validate")
	userAgent   = flag.String("user-agent", "", "override User-Agent")
	timeout     = flag.Duration("timeout", time.Hour, "overall RPC timeout")
	covSTH      = flag.Bool("coverage-sth", true, "coverage mode: query the live STH for tree_size + coverage%%")
	covGaps     = flag.Bool("coverage-gaps", true, "coverage mode: list missing index ranges")
)

func main() {
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer conn.Close()
	cli := pb.NewCTIngestionServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch *mode {
	case "list":
		runList(ctx, cli)
	case "sth":
		runSTH(ctx, cli)
	case "fetch":
		runFetch(ctx, cli)
	case "coverage":
		runCoverage(ctx, cli)
	case "resolve-issuers":
		runResolveIssuers(ctx, cli)
	case "mirror-roots":
		runMirrorRoots(ctx, cli)
	case "verify":
		runVerify(ctx, cli)
	default:
		log.Fatalf("unknown -mode %q (want list|sth|fetch|coverage|resolve-issuers|mirror-roots|verify)", *mode)
	}
}

func selector() *pb.LogSelector {
	sel := &pb.LogSelector{}
	if *logIDHex != "" {
		id, err := hex.DecodeString(*logIDHex)
		if err != nil {
			log.Fatalf("bad -log-id hex: %v", err)
		}
		sel.LogId = id
	}
	if *url != "" {
		sel.MonitoringUrl = *url
		switch *protocol {
		case "rfc6962":
			sel.Protocol = pb.LogProtocol_LOG_PROTOCOL_RFC6962
		case "static":
			sel.Protocol = pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API
		case "tiles":
			// static-ct-api data tiles over a log with no checkpoint (tree from
			// RFC6962 get-sth); e.g. TrustAsia's experimental tile interface.
			sel.Protocol = pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API_NO_CHECKPOINT
		default:
			log.Fatalf("-url requires -protocol rfc6962|static|tiles")
		}
	}
	if *pubKeyB64 != "" {
		key, err := base64.StdEncoding.DecodeString(*pubKeyB64)
		if err != nil {
			log.Fatalf("bad -pubkey base64: %v", err)
		}
		sel.PublicKey = key
	}
	if len(sel.LogId) == 0 && sel.MonitoringUrl == "" {
		log.Fatalf("need -log-id or (-url + -protocol)")
	}
	return sel
}

func gran() pb.PartitionGranularity {
	if *granularity == "hour" {
		return pb.PartitionGranularity_PARTITION_GRANULARITY_HOUR
	}
	return pb.PartitionGranularity_PARTITION_GRANULARITY_DAY
}

func compression() pb.Compression {
	switch *compress {
	case "gzip":
		return pb.Compression_COMPRESSION_GZIP
	case "none", "":
		return pb.Compression_COMPRESSION_NONE
	default:
		log.Fatalf("-compress must be none|gzip (got %q)", *compress)
		return pb.Compression_COMPRESSION_NONE
	}
}

func runList(ctx context.Context, cli pb.CTIngestionServiceClient) {
	resp, err := cli.GetLogList(ctx, &pb.GetLogListRequest{})
	if err != nil {
		log.Fatalf("GetLogList: %v", err)
	}
	n := 0
	for _, op := range resp.GetOperators() {
		for _, lg := range op.GetLogs() {
			proto := "rfc6962"
			u := lg.GetUrl()
			if lg.GetProtocol() == pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API {
				proto, u = "static", lg.GetMonitoringUrl()
			}
			fmt.Printf("%s  %-8s  %-28s  %s\n", hex.EncodeToString(lg.GetLogId()), proto, op.GetName(), u)
			n++
		}
	}
	fmt.Fprintf(os.Stderr, "%d logs (version %s)\n", n, resp.GetVersion())
}

func runSTH(ctx context.Context, cli pb.CTIngestionServiceClient) {
	resp, err := cli.GetSTH(ctx, &pb.GetSTHRequest{Log: selector()})
	if err != nil {
		log.Fatalf("GetSTH: %v", err)
	}
	fmt.Print(prototext.Format(resp))
}

func runFetch(ctx context.Context, cli pb.CTIngestionServiceClient) {
	if *end <= *start {
		log.Fatalf("need -end > -start (got start=%d end=%d)", *start, *end)
	}
	ua := *userAgent
	resp, err := cli.GetLogEntries(ctx, &pb.GetLogEntriesRequest{
		Log:              selector(),
		StartIndex:       *start,
		EndIndex:         *end,
		TargetQps:        *qps,
		FetchConcurrency: int32(*concurrency),
		PageSize:         int32(*pageSize),
		UserAgent:        ua,
		OutputRoot:       *out,
		Granularity:      gran(),
		DisableKeepAlive: *noKeepAlive,
		Compression:      compression(),
	})
	if err != nil {
		log.Fatalf("GetLogEntries: %v", err)
	}
	fmt.Printf("wrote %d entries (%d bytes), indices [%d, %d]\n",
		resp.GetEntriesWritten(), resp.GetBytesWritten(),
		resp.GetFirstIndex(), resp.GetLastIndex())
}

func runCoverage(ctx context.Context, cli pb.CTIngestionServiceClient) {
	if *out == "" {
		log.Fatalf("coverage mode needs -out (the log's output root to scan)")
	}
	// The disk scan needs no log identity (-out is one log's prefix); a selector is
	// only required to query the live STH.
	var sel *pb.LogSelector
	if *logIDHex != "" || *url != "" {
		sel = selector()
	} else if *covSTH {
		log.Fatalf("coverage with -coverage-sth needs -log-id or -url; for disk-only coverage pass -coverage-sth=false")
	}
	resp, err := cli.CheckCoverage(ctx, &pb.CheckCoverageRequest{
		Log:         sel,
		OutputRoot:  *out,
		QuerySth:    *covSTH,
		IncludeGaps: *covGaps,
	})
	if err != nil {
		log.Fatalf("CheckCoverage: %v", err)
	}
	fmt.Printf("stored entries : %d across %d files\n", resp.GetStoredEntries(), resp.GetPartitionFiles())
	fmt.Printf("frontier       : %d (highest stored index + 1)\n", resp.GetFrontier())
	fmt.Printf("contiguous     : [0, %d)\n", resp.GetContiguousThrough())
	if resp.GetTreeSize() > 0 {
		fmt.Printf("tree size      : %d\n", resp.GetTreeSize())
		fmt.Printf("coverage       : %.4f%%\n", resp.GetCoveragePct())
	} else if resp.GetSthError() != "" {
		fmt.Printf("tree size      : (STH unavailable: %s)\n", resp.GetSthError())
	} else {
		fmt.Printf("tree size      : (not queried)\n")
	}
	if len(resp.GetGaps()) > 0 {
		fmt.Printf("gaps (%d):\n", len(resp.GetGaps()))
		for i, g := range resp.GetGaps() {
			if i >= 20 {
				fmt.Printf("  ... and %d more\n", len(resp.GetGaps())-20)
				break
			}
			fmt.Printf("  [%d, %d)  (%d entries)\n", g.GetStart(), g.GetEnd(), g.GetEnd()-g.GetStart())
		}
	} else {
		fmt.Printf("gaps           : none\n")
	}
}

func runResolveIssuers(ctx context.Context, cli pb.CTIngestionServiceClient) {
	if *out == "" {
		log.Fatalf("resolve-issuers mode needs -out (the static log's output root)")
	}
	// A selector is optional: it's only used as a fallback for the issuer endpoint
	// URL when it isn't recorded in the stored batches.
	var sel *pb.LogSelector
	if *logIDHex != "" || *url != "" {
		sel = selector()
	}
	resp, err := cli.ResolveIssuers(ctx, &pb.ResolveIssuersRequest{
		Log:              sel,
		OutputRoot:       *out,
		TargetQps:        *qps,
		FetchConcurrency: int32(*concurrency),
		UserAgent:        *userAgent,
		DryRun:           *dryRun,
	})
	if err != nil {
		log.Fatalf("ResolveIssuers: %v", err)
	}
	missing := resp.GetReferenced() - resp.GetAlreadyPresent()
	fmt.Printf("referenced issuers : %d\n", resp.GetReferenced())
	fmt.Printf("already present    : %d\n", resp.GetAlreadyPresent())
	if *dryRun {
		fmt.Printf("missing            : %d (dry-run; nothing fetched)\n", missing)
	} else {
		fmt.Printf("fetched + stored   : %d\n", resp.GetFetched())
		fmt.Printf("failed             : %d\n", resp.GetFailed())
	}
	for _, e := range resp.GetErrors() {
		fmt.Printf("  ! %s\n", e)
	}
}

func runMirrorRoots(ctx context.Context, cli pb.CTIngestionServiceClient) {
	if *out == "" {
		log.Fatalf("mirror-roots mode needs -out (the log's output root)")
	}
	resp, err := cli.MirrorRoots(ctx, &pb.MirrorRootsRequest{
		Log:        selector(),
		OutputRoot: *out,
		TargetQps:  *qps,
		UserAgent:  *userAgent,
	})
	if err != nil {
		log.Fatalf("MirrorRoots: %v", err)
	}
	fmt.Printf("accepted roots : %d\n", resp.GetTotal())
	fmt.Printf("already present: %d\n", resp.GetAlreadyPresent())
	fmt.Printf("stored         : %d\n", resp.GetStored())
	if resp.GetError() != "" {
		fmt.Printf("error          : %s\n", resp.GetError())
	}
}

func runVerify(ctx context.Context, cli pb.CTIngestionServiceClient) {
	if *out == "" || *index < 0 {
		log.Fatalf("verify mode needs -out and -index >= 0")
	}
	resp, err := cli.VerifyEntry(ctx, &pb.VerifyEntryRequest{OutputRoot: *out, Index: *index})
	if err != nil {
		log.Fatalf("VerifyEntry: %v", err)
	}
	status := "INVALID"
	if resp.GetValid() {
		status = "VALID"
	}
	fmt.Printf("entry %d: %s\n", *index, status)
	fmt.Printf("  leaf   : %s\n", resp.GetLeafSubject())
	for i, c := range resp.GetChainSubjects() {
		fmt.Printf("  chain%d : %s\n", i, c)
	}
	if resp.GetAnchorSubject() != "" {
		fmt.Printf("  anchor : %s\n", resp.GetAnchorSubject())
	}
	fmt.Printf("  valid at SCT time: %v\n", resp.GetWithinValidity())
	if resp.GetReason() != "" {
		fmt.Printf("  reason : %s\n", resp.GetReason())
	}
}
