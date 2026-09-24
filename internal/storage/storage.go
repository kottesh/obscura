// Package storage implements the Obscura server file model (spec section 5)
// and the FileStore interface (spec section 9), backed by SQLite via the
// pure-Go, cgo-free modernc.org/sqlite driver.
//
// The store holds one row and one encrypted byte stream per upload. It never
// sees plaintext, content keys, or receiver private keys. Authorization is
// enforced in SQL (spec sections 6.2 and 11): list queries filter by owner or
// receiver, and deletion succeeds only for the stored owner. Missing ids and
// unauthorized access return the same sentinel ErrNotFound so callers cannot
// distinguish the two.
package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a file id does not exist or the caller is not
// authorized to act on it. Missing and unauthorized ids share this single
// sentinel so the two cases are indistinguishable to callers (spec 6.2, 11).
var ErrNotFound = errors.New("file not found")

// ErrTooLarge is returned when uploaded content exceeds MaxContentSize. When it
// occurs no row is committed (spec 6.3 "file too large").
var ErrTooLarge = errors.New("file too large")

// MaxContentSize is the default maximum encrypted content size accepted by
// Create, in bytes. Uploads larger than this are rejected with ErrTooLarge and
// leave no committed row (spec section 11 upload size limit).
const MaxContentSize = 512 << 20 // 512 MiB

// idAlphabet is a URL-safe, ambiguity-reduced alphabet used for file ids. It
// is the standard NanoID-style alphabet excluding no characters here; every id
// character is drawn uniformly from it using crypto/rand.
const idAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"

// idLength is the number of characters in a generated file id. With a 64-symbol
// alphabet this yields 96 bits of entropy, ample for collision resistance.
const idLength = 16

// CarrierType records whether an upload is a direct encrypted package or an
// encrypted package embedded in a PNG carrier (spec section 5).
type CarrierType string

const (
	// PackageCarrier is a direct EncryptedFile package upload.
	PackageCarrier CarrierType = "package"
	// PNGCarrier is an EncryptedFile package embedded in a generated PNG.
	PNGCarrier CarrierType = "png"
)

// Valid reports whether the carrier type is one of the recognized values.
func (c CarrierType) Valid() bool {
	return c == PackageCarrier || c == PNGCarrier
}

// FileRecord is one server-side file record (spec section 5). It binds an
// authenticated owner to a single receiver and carries only metadata; the
// encrypted content is streamed in via Create and out via OpenContent and is
// never held on the struct.
type FileRecord struct {
	// ID is a random NanoID-style identifier generated from crypto/rand.
	ID string
	// CreatedAt is the record creation time (UTC).
	CreatedAt time.Time
	// UpdatedAt is the last update time (UTC).
	UpdatedAt time.Time
	// Size is the encrypted content size in bytes.
	Size uint64
	// OwnerUserID is BLAKE3(owner sign_pk), derived server-side from the
	// authenticated SSH key, never client-supplied.
	OwnerUserID [32]byte
	// ReceiverUserID is BLAKE3(receiver sign_pk).
	ReceiverUserID [32]byte
	// DisplayName is optional sender-supplied metadata; it may be empty and is
	// never trusted as a filesystem path.
	DisplayName string
	// CarrierType is package or png.
	CarrierType CarrierType
}

// FileStore is the server storage interface (spec section 9). Implementations
// stream content, commit atomically, and authorize in the query layer.
type FileStore interface {
	Create(ctx context.Context, record *FileRecord, content io.Reader) error
	Find(ctx context.Context, id string) (*FileRecord, error)
	OpenContent(ctx context.Context, id string) (io.ReadCloser, error)
	ListOwned(ctx context.Context, userID [32]byte) ([]FileRecord, error)
	ListReceived(ctx context.Context, userID [32]byte) ([]FileRecord, error)
	Delete(ctx context.Context, id string, ownerUserID [32]byte) error
}

// NewID returns a fresh file id: idLength characters drawn uniformly from
// idAlphabet using crypto/rand. The alphabet length (64) divides 256 evenly so
// each random byte maps to one symbol without modulo bias.
func NewID() (string, error) {
	buf := make([]byte, idLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("storage: generate id: %w", err)
	}
	out := make([]byte, idLength)
	for i, b := range buf {
		out[i] = idAlphabet[int(b)%len(idAlphabet)]
	}
	return string(out), nil
}

// SQLiteStore is a SQLite-backed FileStore using the pure-Go modernc driver.
type SQLiteStore struct {
	db *sql.DB
	// maxContentSize is the upload cap enforced by Create.
	maxContentSize int64
}

// compile-time assertion that SQLiteStore satisfies FileStore.
var _ FileStore = (*SQLiteStore)(nil)

const schema = `
CREATE TABLE IF NOT EXISTS files (
	id                TEXT PRIMARY KEY NOT NULL,
	created_at        INTEGER NOT NULL,
	updated_at        INTEGER NOT NULL,
	size              INTEGER NOT NULL,
	owner_user_id     BLOB NOT NULL,
	receiver_user_id  BLOB NOT NULL,
	display_name      TEXT NOT NULL DEFAULT '',
	carrier_type      TEXT NOT NULL,
	encrypted_content BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_owner    ON files(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_files_receiver ON files(receiver_user_id);
`

// Open opens (or creates) a SQLite database at dsn and applies the schema. Pass
// a file path for a persistent store. The returned store uses MaxContentSize.
//
// The connection pool is limited to a single connection so that a shared in-memory
// database (":memory:") behaves as one durable database across queries, matching
// the spec's single-connection test guidance.
func Open(ctx context.Context, dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open sqlite: %w", err)
	}
	// A single connection keeps an in-memory DB alive and serializes writes,
	// which SQLite requires anyway.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: apply schema: %w", err)
	}

	return &SQLiteStore{db: db, maxContentSize: MaxContentSize}, nil
}

// SetMaxContentSize overrides the upload cap for this store. A value <= 0 is
// ignored. Intended for tests and deployment tuning.
func (s *SQLiteStore) SetMaxContentSize(n int64) {
	if n > 0 {
		s.maxContentSize = n
	}
}

// Close closes the underlying database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Create streams content into the store and commits atomically in a single
// transaction. The full stream is read and validated against the size cap
// before commit; on any error the transaction is rolled back and no row
// persists (spec sections 9, 11). If record.ID is empty a fresh id is
// generated with crypto/rand; the assigned id and timestamps are written back
// to record on success.
func (s *SQLiteStore) Create(ctx context.Context, record *FileRecord, content io.Reader) error {
	if record == nil {
		return errors.New("storage: create: nil record")
	}
	if content == nil {
		return errors.New("storage: create: nil content")
	}
	if !record.CarrierType.Valid() {
		return fmt.Errorf("storage: create: invalid carrier type %q", record.CarrierType)
	}

	id := record.ID
	if id == "" {
		var err error
		if id, err = NewID(); err != nil {
			return err
		}
	}

	// Read the full stream with a hard cap. We read maxContentSize+1 bytes so
	// that any overflow is detected without allocating the entire oversized
	// payload. Nothing is written to the database until the stream is fully
	// validated, so an oversized or interrupted upload leaves no row.
	limited := io.LimitReader(content, s.maxContentSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("storage: create: read content: %w", err)
	}
	if int64(len(data)) > s.maxContentSize {
		return ErrTooLarge
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: create: begin tx: %w", err)
	}
	// Roll back on any early return; a no-op after a successful Commit.
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO files
			(id, created_at, updated_at, size, owner_user_id, receiver_user_id, display_name, carrier_type, encrypted_content)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		now.UnixNano(),
		now.UnixNano(),
		int64(len(data)),
		record.OwnerUserID[:],
		record.ReceiverUserID[:],
		record.DisplayName,
		string(record.CarrierType),
		data,
	)
	if err != nil {
		return fmt.Errorf("storage: create: insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: create: commit: %w", err)
	}

	record.ID = id
	record.Size = uint64(len(data))
	record.CreatedAt = now
	record.UpdatedAt = now
	return nil
}

// scanRecord reads a metadata row (no content) into a FileRecord.
func scanRecord(row interface{ Scan(...any) error }) (*FileRecord, error) {
	var (
		rec       FileRecord
		createdNs int64
		updatedNs int64
		size      int64
		owner     []byte
		receiver  []byte
		carrier   string
	)
	if err := row.Scan(&rec.ID, &createdNs, &updatedNs, &size, &owner, &receiver, &rec.DisplayName, &carrier); err != nil {
		return nil, err
	}
	if len(owner) != 32 || len(receiver) != 32 {
		return nil, fmt.Errorf("storage: corrupt user id length owner=%d receiver=%d", len(owner), len(receiver))
	}
	rec.CreatedAt = time.Unix(0, createdNs).UTC()
	rec.UpdatedAt = time.Unix(0, updatedNs).UTC()
	rec.Size = uint64(size)
	copy(rec.OwnerUserID[:], owner)
	copy(rec.ReceiverUserID[:], receiver)
	rec.CarrierType = CarrierType(carrier)
	return &rec, nil
}

const selectMetaCols = `id, created_at, updated_at, size, owner_user_id, receiver_user_id, display_name, carrier_type`

// Find returns the metadata record for id, or ErrNotFound if it does not exist.
func (s *SQLiteStore) Find(ctx context.Context, id string) (*FileRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+selectMetaCols+` FROM files WHERE id = ?`, id)
	rec, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: find: %w", err)
	}
	return rec, nil
}

// OpenContent returns a streaming reader over the encrypted content for id, or
// ErrNotFound if it does not exist. The reader must be closed by the caller.
func (s *SQLiteStore) OpenContent(ctx context.Context, id string) (io.ReadCloser, error) {
	// modernc.org/sqlite exposes incremental BLOB I/O only indirectly; to keep
	// downloads streaming without loading the whole blob eagerly we hand back a
	// reader that pulls the column value lazily on first read.
	return newBlobReader(ctx, s.db, id), nil
}

// ListOwned returns records owned by userID, filtered in SQL (spec 11).
func (s *SQLiteStore) ListOwned(ctx context.Context, userID [32]byte) ([]FileRecord, error) {
	return s.listBy(ctx, "owner_user_id", userID)
}

// ListReceived returns records addressed to userID, filtered in SQL (spec 11).
func (s *SQLiteStore) ListReceived(ctx context.Context, userID [32]byte) ([]FileRecord, error) {
	return s.listBy(ctx, "receiver_user_id", userID)
}

// listBy runs a metadata query filtered by the given user-id column.
func (s *SQLiteStore) listBy(ctx context.Context, column string, userID [32]byte) ([]FileRecord, error) {
	// column is not user input; it is one of two package-controlled constants.
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectMetaCols+` FROM files WHERE `+column+` = ? ORDER BY created_at ASC`,
		userID[:])
	if err != nil {
		return nil, fmt.Errorf("storage: list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []FileRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: list scan: %w", err)
		}
		out = append(out, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list rows: %w", err)
	}
	return out, nil
}

// Delete removes the record for id only when ownerUserID matches the stored
// owner. A missing id and a wrong owner both return ErrNotFound and leave any
// existing row intact (spec 6.2, 11).
func (s *SQLiteStore) Delete(ctx context.Context, id string, ownerUserID [32]byte) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM files WHERE id = ? AND owner_user_id = ?`,
		id, ownerUserID[:])
	if err != nil {
		return fmt.Errorf("storage: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: delete: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
