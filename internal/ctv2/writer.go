package ctv2

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Writer persists a single partition file. Implementations must treat writes as
// immutable (write-once): a job owns its index ranges and never rewrites them.
// LocalFSWriter is the only backend today; an R2/S3 backend can drop in behind
// this interface without touching the fetch/partition code.
type Writer interface {
	// Put writes data at relPath (slash-separated, relative to the backend root).
	Put(ctx context.Context, relPath string, data []byte) error

	// PutIfAbsent writes data at relPath only if nothing is there yet; it is a
	// no-op (nil error) when the path already exists. Used for the content-
	// addressed issuer store, where the same chain cert may be written by many
	// concurrent batches/jobs and the bytes are identical by construction, so it
	// must be safe for concurrent writes to the same path.
	PutIfAbsent(ctx context.Context, relPath string, data []byte) error
}

// LocalFSWriter writes partition files under Root via a tmp-file + atomic rename,
// refusing to overwrite an existing partition.
type LocalFSWriter struct {
	Root string
}

func (w *LocalFSWriter) Put(_ context.Context, relPath string, data []byte) error {
	full := filepath.Join(w.Root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(full); err == nil {
		return fmt.Errorf("partition already exists (immutable): %s", full)
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, full); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (w *LocalFSWriter) PutIfAbsent(_ context.Context, relPath string, data []byte) error {
	full := filepath.Join(w.Root, filepath.FromSlash(relPath))
	if _, err := os.Stat(full); err == nil {
		return nil // already present; content-addressed, so the bytes match
	}
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// A per-write unique temp name keeps concurrent writers to the same content
	// address from clobbering each other's temp file; the final rename is atomic
	// and last-writer-wins is harmless (identical bytes).
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, full); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
