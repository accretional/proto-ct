package ctv2

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"google.golang.org/protobuf/proto"
)

// leafDay returns the partition sub-path (relative to the output root) for a leaf
// timestamp at the requested granularity: "YYYY-MM-DD" or "YYYY-MM-DD/HH" (UTC).
func leafDay(tsMs int64, g pb.PartitionGranularity) string {
	t := time.UnixMilli(tsMs).UTC()
	if g == pb.PartitionGranularity_PARTITION_GRANULARITY_HOUR {
		return path.Join(t.Format("2006-01-02"), t.Format("15"))
	}
	return t.Format("2006-01-02")
}

// batchSink writes contiguous, index-ordered batches of leaves to immutable
// binary-protobuf files, relative to the writer's root: <day>/<firstIdx>-<lastIdx>.binpb.
// The caller owns the log-level prefix (the output root is per-log), so no log-id
// component is added here. Because the fetcher hands it disjoint batches of
// consecutive indices, every file covers a disjoint contiguous index range and a
// re-run of the same (log, range, batch size, granularity) produces byte-identical
// files (deterministic marshal). The log identity is still recorded inside each
// file via RawLogEntryBatch.log. Safe for concurrent callers.
type batchSink struct {
	w           Writer
	meta        *pb.LogMeta
	gran        pb.PartitionGranularity
	issuers     *issuerStore // shared issuer store for RFC6962 chain certs; nil if unused
	marshalOpts proto.MarshalOptions

	mu             sync.Mutex
	entriesWritten int64
	bytesWritten   int64
	firstIndex     int64 // overall min, -1 until first write
	lastIndex      int64 // overall max, -1 until first write
}

func newBatchSink(w Writer, meta *pb.LogMeta, gran pb.PartitionGranularity, issuers *issuerStore) *batchSink {
	return &batchSink{
		w:           w,
		meta:        meta,
		gran:        gran,
		issuers:     issuers,
		marshalOpts: proto.MarshalOptions{Deterministic: true},
		firstIndex:  -1,
		lastIndex:   -1,
	}
}

// writeBatch persists one contiguous, index-ordered batch, splitting it into a
// file per contiguous same-day run. Any issuer-chain certs carried with the batch
// are written to the shared issuer store first, so a stored leaf's chain
// fingerprints always resolve (an orphaned issuer cert on a crash is harmless; a
// dangling fingerprint would not be).
func (s *batchSink) writeBatch(ctx context.Context, b entryBatch) error {
	if s.issuers != nil && len(b.chains) > 0 {
		if err := s.issuers.put(ctx, b.chains); err != nil {
			return err
		}
	}
	entries := b.entries
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
	relPath := path.Join(day, encodeBase36(first)+"-"+encodeBase36(last)+".binpb")
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
