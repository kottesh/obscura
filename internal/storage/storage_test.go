package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

// newTestStore opens a fresh file-backed SQLite store in a temp dir. A file DB
// (rather than :memory:) keeps the schema durable across the single pooled
// connection and mirrors real deployment.
func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "obscura-test.db")
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// uid builds a distinct 32-byte user id from a seed byte for readable tests.
func uid(b byte) [32]byte {
	var u [32]byte
	for i := range u {
		u[i] = b
	}
	return u
}

func mustCreate(t *testing.T, s *SQLiteStore, rec *FileRecord, content []byte) {
	t.Helper()
	if err := s.Create(context.Background(), rec, bytes.NewReader(content)); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func readContent(t *testing.T, s *SQLiteStore, id string) []byte {
	t.Helper()
	rc, err := s.OpenContent(context.Background(), id)
	if err != nil {
		t.Fatalf("OpenContent: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	return got
}

func TestCreateFindRoundTrip(t *testing.T) {
	s := newTestStore(t)
	owner, receiver := uid(1), uid(2)

	rec := &FileRecord{
		OwnerUserID:    owner,
		ReceiverUserID: receiver,
		DisplayName:    "notes.txt",
		CarrierType:    PackageCarrier,
	}
	content := []byte("hello obscura")
	mustCreate(t, s, rec, content)

	if rec.ID == "" {
		t.Fatal("Create did not assign an id")
	}
	if rec.Size != uint64(len(content)) {
		t.Fatalf("Size = %d, want %d", rec.Size, len(content))
	}
	if rec.CreatedAt.IsZero() || rec.UpdatedAt.IsZero() {
		t.Fatal("timestamps not set")
	}

	got, err := s.Find(context.Background(), rec.ID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != rec.ID ||
		got.OwnerUserID != owner ||
		got.ReceiverUserID != receiver ||
		got.DisplayName != "notes.txt" ||
		got.CarrierType != PackageCarrier ||
		got.Size != uint64(len(content)) {
		t.Fatalf("Find returned %+v, want match of %+v", got, rec)
	}
}

func TestOpenContentByteExact(t *testing.T) {
	s := newTestStore(t)

	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"small", 13},
		{"one_chunk_minus_one", blobChunkSize - 1},
		{"exact_chunk", blobChunkSize},
		{"multi_chunk", blobChunkSize*3 + 123},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := make([]byte, tt.size)
			if _, err := rand.Read(content); err != nil {
				t.Fatalf("rand: %v", err)
			}
			rec := &FileRecord{
				OwnerUserID:    uid(1),
				ReceiverUserID: uid(2),
				CarrierType:    PNGCarrier,
			}
			mustCreate(t, s, rec, content)

			got := readContent(t, s, rec.ID)
			if !bytes.Equal(got, content) {
				t.Fatalf("content mismatch: got %d bytes, want %d bytes", len(got), len(content))
			}
		})
	}
}

func TestListFiltersByUser(t *testing.T) {
	s := newTestStore(t)
	alice, bob, carol := uid(1), uid(2), uid(3)

	// alice -> bob, alice -> carol, bob -> alice
	specs := []struct {
		owner, receiver [32]byte
	}{
		{alice, bob},
		{alice, carol},
		{bob, alice},
	}
	for i, sp := range specs {
		rec := &FileRecord{OwnerUserID: sp.owner, ReceiverUserID: sp.receiver, CarrierType: PackageCarrier}
		mustCreate(t, s, rec, []byte{byte(i)})
	}

	tests := []struct {
		name    string
		list    func(context.Context, [32]byte) ([]FileRecord, error)
		user    [32]byte
		wantLen int
		checkFn func(FileRecord) bool
	}{
		{"alice owned", s.ListOwned, alice, 2, func(r FileRecord) bool { return r.OwnerUserID == alice }},
		{"bob owned", s.ListOwned, bob, 1, func(r FileRecord) bool { return r.OwnerUserID == bob }},
		{"carol owned", s.ListOwned, carol, 0, nil},
		{"alice received", s.ListReceived, alice, 1, func(r FileRecord) bool { return r.ReceiverUserID == alice }},
		{"bob received", s.ListReceived, bob, 1, func(r FileRecord) bool { return r.ReceiverUserID == bob }},
		{"carol received", s.ListReceived, carol, 1, func(r FileRecord) bool { return r.ReceiverUserID == carol }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.list(context.Background(), tt.user)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tt.wantLen)
			}
			for _, r := range got {
				if tt.checkFn != nil && !tt.checkFn(r) {
					t.Fatalf("row %+v did not match filter", r)
				}
			}
		})
	}
}

func TestDeleteAuthorization(t *testing.T) {
	s := newTestStore(t)
	owner, other := uid(1), uid(9)

	tests := []struct {
		name       string
		deleteAs   [32]byte
		wantErr    error
		wantExists bool
	}{
		{"non-owner denied", other, ErrNotFound, true},
		{"owner allowed", owner, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &FileRecord{OwnerUserID: owner, ReceiverUserID: uid(2), CarrierType: PackageCarrier}
			mustCreate(t, s, rec, []byte("payload"))

			err := s.Delete(context.Background(), rec.ID, tt.deleteAs)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Delete err = %v, want %v", err, tt.wantErr)
			}

			_, findErr := s.Find(context.Background(), rec.ID)
			if tt.wantExists && findErr != nil {
				t.Fatalf("row should still exist, Find err = %v", findErr)
			}
			if !tt.wantExists && !errors.Is(findErr, ErrNotFound) {
				t.Fatalf("row should be gone, Find err = %v", findErr)
			}
		})
	}
}

func TestDeleteMissingIsNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.Delete(context.Background(), "does-not-exist", uid(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing err = %v, want ErrNotFound", err)
	}
}

func TestFindAndOpenMissingIsNotFound(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.Find(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Find missing err = %v, want ErrNotFound", err)
	}

	// OpenContent is lazy; the ErrNotFound surfaces on first read.
	rc, err := s.OpenContent(context.Background(), "nope")
	if err != nil {
		t.Fatalf("OpenContent returned setup error: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read of missing content err = %v, want ErrNotFound", err)
	}
}

func TestOversizedContentRejectedNoRow(t *testing.T) {
	s := newTestStore(t)
	s.SetMaxContentSize(1024)

	tests := []struct {
		name    string
		size    int
		wantErr error
	}{
		{"at limit ok", 1024, nil},
		{"one over rejected", 1025, ErrTooLarge},
		{"far over rejected", 1 << 20, ErrTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := make([]byte, tt.size)
			rec := &FileRecord{OwnerUserID: uid(1), ReceiverUserID: uid(2), CarrierType: PackageCarrier}
			err := s.Create(context.Background(), rec, bytes.NewReader(content))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Create err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				// Nothing must have been committed: no id assigned and no way to find.
				if rec.ID != "" {
					if _, ferr := s.Find(context.Background(), rec.ID); !errors.Is(ferr, ErrNotFound) {
						t.Fatalf("oversized upload left a row, Find err = %v", ferr)
					}
				}
			}
		})
	}

	// Confirm exactly one row (the at-limit success) persisted across all cases.
	owned, err := s.ListOwned(context.Background(), uid(1))
	if err != nil {
		t.Fatalf("ListOwned: %v", err)
	}
	if len(owned) != 1 {
		t.Fatalf("persisted rows = %d, want 1 (only the at-limit upload)", len(owned))
	}
}

func TestIDsUniqueAndFromCryptoRand(t *testing.T) {
	s := newTestStore(t)
	const n = 2000
	seen := make(map[string]struct{}, n)

	for i := 0; i < n; i++ {
		rec := &FileRecord{OwnerUserID: uid(1), ReceiverUserID: uid(2), CarrierType: PackageCarrier}
		mustCreate(t, s, rec, []byte{byte(i)})
		if len(rec.ID) != idLength {
			t.Fatalf("id %q length = %d, want %d", rec.ID, len(rec.ID), idLength)
		}
		if _, dup := seen[rec.ID]; dup {
			t.Fatalf("duplicate id generated: %q", rec.ID)
		}
		seen[rec.ID] = struct{}{}
	}
}

func TestCreateRejectsInvalidCarrier(t *testing.T) {
	s := newTestStore(t)
	rec := &FileRecord{OwnerUserID: uid(1), ReceiverUserID: uid(2), CarrierType: CarrierType("bogus")}
	if err := s.Create(context.Background(), rec, bytes.NewReader(nil)); err == nil {
		t.Fatal("expected error for invalid carrier type")
	}
	// Invalid carrier must not persist anything.
	owned, _ := s.ListOwned(context.Background(), uid(1))
	if len(owned) != 0 {
		t.Fatalf("invalid carrier left %d rows, want 0", len(owned))
	}
}

// errReader fails partway to simulate an interrupted upload.
type errReader struct {
	data []byte
	pos  int
	fail int
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.pos >= e.fail {
		return 0, errors.New("simulated stream failure")
	}
	n := copy(p, e.data[e.pos:e.fail])
	e.pos += n
	return n, nil
}

func TestInterruptedUploadLeavesNoRow(t *testing.T) {
	s := newTestStore(t)
	rec := &FileRecord{OwnerUserID: uid(1), ReceiverUserID: uid(2), CarrierType: PackageCarrier}
	r := &errReader{data: make([]byte, 100), fail: 40}

	if err := s.Create(context.Background(), rec, r); err == nil {
		t.Fatal("expected error from interrupted upload")
	}
	owned, err := s.ListOwned(context.Background(), uid(1))
	if err != nil {
		t.Fatalf("ListOwned: %v", err)
	}
	if len(owned) != 0 {
		t.Fatalf("interrupted upload left %d rows, want 0", len(owned))
	}
}
