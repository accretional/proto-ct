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
	userAgent   = flag.String("user-agent", "", "override User-Agent")
	timeout     = flag.Duration("timeout", time.Hour, "overall RPC timeout")
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
	default:
		log.Fatalf("unknown -mode %q (want list|sth|fetch)", *mode)
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
		default:
			log.Fatalf("-url requires -protocol rfc6962|static")
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
	})
	if err != nil {
		log.Fatalf("GetLogEntries: %v", err)
	}
	fmt.Printf("wrote %d entries (%d bytes) across %d partitions, indices [%d, %d]\n",
		resp.GetEntriesWritten(), resp.GetBytesWritten(), len(resp.GetPartitions()),
		resp.GetFirstIndex(), resp.GetLastIndex())
	for _, p := range resp.GetPartitions() {
		fmt.Printf("  %s  (%d entries)\n", p.GetPath(), p.GetEntryCount())
	}
}
