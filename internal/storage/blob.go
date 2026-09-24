package storage

import (
	"context"
	"database/sql"
	"errors"
	"io"
)

// blobChunkSize is how many bytes each incremental read pulls from the stored
// encrypted content. Downloads therefore stream in bounded chunks rather than
// loading the whole blob into memory (spec sections 9, 11).
const blobChunkSize = 64 << 10 // 64 KiB

// blobReader streams the encrypted_content column for a file id in bounded
// chunks using SQLite's substr() so no single read materializes the full blob.
// It is lazy: the row's existence is confirmed on the first Read, and a missing
// id surfaces as ErrNotFound from that first Read.
type blobReader struct {
	ctx    context.Context
	db     *sql.DB
	id     string
	offset int64 // 1-based byte offset for the next substr() call
	buf    []byte
	done   bool
	err    error
}

func newBlobReader(ctx context.Context, db *sql.DB, id string) *blobReader {
	return &blobReader{ctx: ctx, db: db, id: id, offset: 1}
}

// Read implements io.Reader, pulling successive chunks from SQLite on demand.
func (b *blobReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	for len(b.buf) == 0 {
		if b.done {
			return 0, io.EOF
		}
		if err := b.fetch(); err != nil {
			b.err = err
			return 0, err
		}
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

// fetch loads the next chunk, setting done at end of content.
func (b *blobReader) fetch() error {
	// substr(blob, offset, len) returns up to len bytes starting at the 1-based
	// offset. An empty result means we have consumed the whole blob.
	var chunk []byte
	row := b.db.QueryRowContext(b.ctx,
		`SELECT substr(encrypted_content, ?, ?) FROM files WHERE id = ?`,
		b.offset, blobChunkSize, b.id)
	if err := row.Scan(&chunk); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if len(chunk) == 0 {
		b.done = true
		return nil
	}
	b.buf = chunk
	b.offset += int64(len(chunk))
	if len(chunk) < blobChunkSize {
		// A short chunk means we reached the end of the content.
		b.done = true
	}
	return nil
}

// Close implements io.Closer. The reader holds no long-lived resources, so this
// only marks the reader exhausted.
func (b *blobReader) Close() error {
	b.done = true
	b.buf = nil
	if b.err == nil {
		b.err = errors.New("storage: read on closed content reader")
	}
	return nil
}
