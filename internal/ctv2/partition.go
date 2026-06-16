package ctv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"google.golang.org/protobuf/encoding/prototext"
)

// defaultMaxEntriesPerFile bounds how many leaves accumulate in one partition
// file before it is flushed (keeps memory + file sizes bounded on big ranges).
const defaultMaxEntriesPerFile = 50_000

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
		// Last resort: hash whatever selector text we have.
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

// partitionWriter buckets RawLogEntries by (logSlug / leafDay) and flushes each
// bucket to an immutable textproto file named <firstIdx>-<lastIdx>.textpb.
type partitionWriter struct {
	w           Writer
	meta        *pb.LogMeta
	slug        string
	gran        pb.PartitionGranularity
	maxEntries  int
	marshalOpts prototext.MarshalOptions

	bufs map[string]*partBuf

	manifests      []*pb.PartitionManifest
	entriesWritten int64
	bytesWritten   int64
}

type partBuf struct {
	day     string // leafDay, relative to slug
	entries []*pb.RawLogEntry
}

func newPartitionWriter(w Writer, meta *pb.LogMeta, gran pb.PartitionGranularity, maxEntries int) *partitionWriter {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntriesPerFile
	}
	return &partitionWriter{
		w:           w,
		meta:        meta,
		slug:        logSlug(meta),
		gran:        gran,
		maxEntries:  maxEntries,
		marshalOpts: prototext.MarshalOptions{Multiline: true, Indent: "  "},
		bufs:        make(map[string]*partBuf),
	}
}

// add appends one entry to its partition bucket, flushing the bucket if it is full.
func (p *partitionWriter) add(ctx context.Context, e *pb.RawLogEntry) error {
	day := leafDay(e.GetTimestampMs(), p.gran)
	b := p.bufs[day]
	if b == nil {
		b = &partBuf{day: day}
		p.bufs[day] = b
	}
	b.entries = append(b.entries, e)
	if len(b.entries) >= p.maxEntries {
		return p.flushBucket(ctx, day)
	}
	return nil
}

func (p *partitionWriter) flushBucket(ctx context.Context, day string) error {
	b := p.bufs[day]
	if b == nil || len(b.entries) == 0 {
		return nil
	}
	first := b.entries[0].GetIndex()
	last := b.entries[len(b.entries)-1].GetIndex()
	batch := &pb.RawLogEntryBatch{Log: p.meta, Entries: b.entries}
	data, err := p.marshalOpts.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch %s [%d,%d]: %w", day, first, last, err)
	}
	relPath := path.Join(p.slug, day, fmt.Sprintf("%d-%d.textpb", first, last))
	if err := p.w.Put(ctx, relPath, data); err != nil {
		return err
	}
	p.manifests = append(p.manifests, &pb.PartitionManifest{
		Path:         relPath,
		LeafDay:      day,
		FirstIndex:   first,
		LastIndex:    last,
		EntryCount:   int64(len(b.entries)),
		BytesWritten: int64(len(data)),
	})
	p.entriesWritten += int64(len(b.entries))
	p.bytesWritten += int64(len(data))
	delete(p.bufs, day)
	return nil
}

// flushAll flushes every remaining bucket (deterministic order).
func (p *partitionWriter) flushAll(ctx context.Context) error {
	days := make([]string, 0, len(p.bufs))
	for d := range p.bufs {
		days = append(days, d)
	}
	sort.Strings(days)
	for _, d := range days {
		if err := p.flushBucket(ctx, d); err != nil {
			return err
		}
	}
	return nil
}
