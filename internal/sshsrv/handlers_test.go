package sshsrv

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/storage"
)

// fakeSession is an in-memory session for testing the handler layer without a
// live SSH connection. stdin feeds reads; stdout/stderr capture writes.
type fakeSession struct {
	stdin    *bytes.Reader
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	exitCode int
	exited   bool
}

func newFakeSession(stdin []byte) *fakeSession {
	return &fakeSession{stdin: bytes.NewReader(stdin)}
}

func (f *fakeSession) Read(p []byte) (int, error)  { return f.stdin.Read(p) }
func (f *fakeSession) Write(p []byte) (int, error) { return f.stdout.Write(p) }
func (f *fakeSession) Stderr() io.Writer           { return &f.stderr }

func (f *fakeSession) Exit(code int) error {
	f.exitCode = code
	f.exited = true
	return nil
}

// newTestStore opens a temp-file SQLite store for an integration-style test.
func newTestStore(t *testing.T) *storage.SQLiteStore {
	t.Helper()
	dsn := "file:" + t.TempDir() + "/test.db"
	store, err := storage.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// testIdentity returns a fresh (address, userID) pair.
func testIdentity(t *testing.T) (addr string, userID [32]byte) {
	t.Helper()
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("new identity: %v", err)
	}
	a, err := id.Address()
	if err != nil {
		t.Fatalf("address: %v", err)
	}
	return a, id.UserID()
}

func TestUploadArgParsing(t *testing.T) {
	validAddr, _ := testIdentity(t)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(t *testing.T, ua uploadArgs)
	}{
		{name: "missing -to", args: []string{}, wantErr: true},
		{name: "missing -to with name", args: []string{"-name", "x"}, wantErr: true},
		{name: "bad base58 -to", args: []string{"-to", "0OIl"}, wantErr: false /* DecodeAddress checks, not parse */},
		{name: "unknown flag typo", args: []string{"-too", validAddr}, wantErr: true},
		{name: "positional arg", args: []string{validAddr}, wantErr: true},
		{name: "carrier non-enum", args: []string{"-to", validAddr, "-carrier", "zip"}, wantErr: true},
		{
			name: "valid package default",
			args: []string{"-to", validAddr},
			check: func(t *testing.T, ua uploadArgs) {
				if ua.carrier != storage.PackageCarrier {
					t.Fatalf("carrier=%q want package", ua.carrier)
				}
			},
		},
		{
			name: "valid png carrier and name",
			args: []string{"-to", validAddr, "-carrier", "png", "-name", "photo.png"},
			check: func(t *testing.T, ua uploadArgs) {
				if ua.carrier != storage.PNGCarrier || ua.name != "photo.png" {
					t.Fatalf("got carrier=%q name=%q", ua.carrier, ua.name)
				}
			},
		},
		{
			name:    "name with ANSI control chars rejected",
			args:    []string{"-to", validAddr, "-name", "evil\x1b[31mred"},
			wantErr: true,
		},
		{
			name:    "name with bidi override rejected",
			args:    []string{"-to", validAddr, "-name", "gpj\u202egnp.txt"},
			wantErr: true,
		},
		{
			name:    "name with zero-width char rejected",
			args:    []string{"-to", validAddr, "-name", "inv\u200bisible"},
			wantErr: true,
		},
		{
			name:    "name too long rejected",
			args:    []string{"-to", validAddr, "-name", strings.Repeat("a", 256)},
			wantErr: true,
		},
		{
			name: "name at max length ok",
			args: []string{"-to", validAddr, "-name", strings.Repeat("a", 255)},
			check: func(t *testing.T, ua uploadArgs) {
				if len(ua.name) != 255 {
					t.Fatalf("name len=%d", len(ua.name))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ua, err := parseUploadArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", ua)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, ua)
			}
		})
	}
}

func TestAuthorizationPredicate(t *testing.T) {
	var owner, receiver, third [32]byte
	owner[0], receiver[0], third[0] = 1, 2, 3
	rec := &storage.FileRecord{OwnerUserID: owner, ReceiverUserID: receiver}

	if !authorizedForDownload(owner, rec) {
		t.Fatal("owner should be authorized")
	}
	if !authorizedForDownload(receiver, rec) {
		t.Fatal("receiver should be authorized")
	}
	if authorizedForDownload(third, rec) {
		t.Fatal("third party must not be authorized")
	}
	if authorizedForDownload(owner, nil) {
		t.Fatal("nil record must not be authorized")
	}
}

// TestDownloadMissingVsUnauthorizedIdentical asserts that a missing id and a
// found-but-unauthorized id produce the identical stderr message AND exit code
// via the centralized not-found exit.
func TestDownloadMissingVsUnauthorizedIdentical(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	ownerAddr, ownerID := testIdentity(t)
	recvAddr, _ := testIdentity(t)
	_, thirdID := testIdentity(t)
	_ = ownerAddr

	// Upload one record owned by ownerID to recvAddr's receiver.
	recvDecoded, err := identity.DecodeAddress(recvAddr)
	if err != nil {
		t.Fatal(err)
	}
	rec := &storage.FileRecord{
		OwnerUserID:    ownerID,
		ReceiverUserID: recvDecoded.UserID,
		CarrierType:    storage.PackageCarrier,
	}
	if err := store.Create(ctx, rec, bytes.NewReader([]byte("ciphertext"))); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Case A: missing id (well-formed but nonexistent).
	missingID := strings.Repeat("a", fileIDLength)
	sA := newFakeSession(nil)
	_ = handleDownload(ctx, sA, store, thirdID, missingID)

	// Case B: existing id, unauthorized caller (third party).
	sB := newFakeSession(nil)
	_ = handleDownload(ctx, sB, store, thirdID, rec.ID)

	if sA.exitCode != sB.exitCode {
		t.Fatalf("exit codes differ: missing=%d unauthorized=%d", sA.exitCode, sB.exitCode)
	}
	if sA.stderr.String() != sB.stderr.String() {
		t.Fatalf("stderr differs: missing=%q unauthorized=%q", sA.stderr.String(), sB.stderr.String())
	}
	if strings.TrimSpace(sA.stderr.String()) != notFoundMessage {
		t.Fatalf("stderr = %q, want %q", sA.stderr.String(), notFoundMessage)
	}
	if sA.stdout.Len() != 0 || sB.stdout.Len() != 0 {
		t.Fatal("no bytes should reach stdout on not-found")
	}
	if sA.exitCode == exitOK {
		t.Fatal("exit must be non-zero")
	}
}

// TestMalformedFileIDIsNotFound asserts a malformed f:<id> yields the same
// not-found result and never falls through to another route.
func TestMalformedFileIDIsNotFound(t *testing.T) {
	store := newTestStore(t)
	_, caller := testIdentity(t)

	s := newFakeSession(nil)
	_ = handleFile(context.Background(), s, store, caller, "not-a-valid-id!", nil)
	if strings.TrimSpace(s.stderr.String()) != notFoundMessage {
		t.Fatalf("stderr = %q, want %q", s.stderr.String(), notFoundMessage)
	}
	if s.exitCode != exitNotFound {
		t.Fatalf("exit=%d want %d", s.exitCode, exitNotFound)
	}

	// Empty id must also be not-found, not upload.
	s2 := newFakeSession(nil)
	_ = handleFile(context.Background(), s2, store, caller, "", nil)
	if strings.TrimSpace(s2.stderr.String()) != notFoundMessage {
		t.Fatalf("empty id stderr = %q, want %q", s2.stderr.String(), notFoundMessage)
	}
}

// TestUploadDownloadDeleteListEndToEnd exercises the handler layer against a
// real store: upload, list (both directions), download (owner+receiver),
// third-party denial, and owner-only delete.
func TestUploadDownloadDeleteListEndToEnd(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	ownerAddr, ownerID := testIdentity(t)
	recvAddr, recvID := testIdentity(t)
	_, thirdID := testIdentity(t)
	_ = ownerAddr

	content := []byte("opaque encrypted bytes")

	// Upload from owner to receiver.
	up := newFakeSession(content)
	_ = handleUpload(ctx, up, store, ownerID, []string{"-to", recvAddr, "-name", "doc.pkg"}, storage.MaxContentSize)
	if up.exitCode != exitOK {
		t.Fatalf("upload exit=%d stderr=%q", up.exitCode, up.stderr.String())
	}
	fileID := strings.TrimSpace(up.stdout.String())
	if !validFileID(fileID) {
		t.Fatalf("upload returned invalid id %q", fileID)
	}

	// Owner download.
	dOwner := newFakeSession(nil)
	_ = handleDownload(ctx, dOwner, store, ownerID, fileID)
	if dOwner.exitCode != exitOK || !bytes.Equal(dOwner.stdout.Bytes(), content) {
		t.Fatalf("owner download failed: exit=%d bytes=%q", dOwner.exitCode, dOwner.stdout.Bytes())
	}
	if dOwner.stderr.Len() != 0 {
		t.Fatalf("owner download wrote to stderr: %q", dOwner.stderr.String())
	}

	// Receiver download.
	dRecv := newFakeSession(nil)
	_ = handleDownload(ctx, dRecv, store, recvID, fileID)
	if dRecv.exitCode != exitOK || !bytes.Equal(dRecv.stdout.Bytes(), content) {
		t.Fatalf("receiver download failed: exit=%d", dRecv.exitCode)
	}

	// Third party download -> not found.
	dThird := newFakeSession(nil)
	_ = handleDownload(ctx, dThird, store, thirdID, fileID)
	if dThird.exitCode != exitNotFound || strings.TrimSpace(dThird.stderr.String()) != notFoundMessage {
		t.Fatalf("third download: exit=%d stderr=%q", dThird.exitCode, dThird.stderr.String())
	}

	// list -sent for owner should include the record; name must be clean.
	lSent := newFakeSession(nil)
	_ = handleList(ctx, lSent, store, ownerID, []string{"-sent"})
	if lSent.exitCode != exitOK || !strings.Contains(lSent.stdout.String(), fileID) {
		t.Fatalf("list -sent missing record: %q", lSent.stdout.String())
	}
	if !strings.Contains(lSent.stdout.String(), "doc.pkg") {
		t.Fatalf("list -sent missing name: %q", lSent.stdout.String())
	}

	// list -received for receiver should include the record.
	lRecv := newFakeSession(nil)
	_ = handleList(ctx, lRecv, store, recvID, []string{"-received"})
	if !strings.Contains(lRecv.stdout.String(), fileID) {
		t.Fatalf("list -received missing record: %q", lRecv.stdout.String())
	}

	// Receiver cannot delete (owner-only) -> not found.
	delRecv := newFakeSession(nil)
	_ = handleDelete(ctx, delRecv, store, recvID, fileID)
	if delRecv.exitCode != exitNotFound {
		t.Fatalf("receiver delete: exit=%d want not-found", delRecv.exitCode)
	}
	// Record still present.
	if _, err := store.Find(ctx, fileID); err != nil {
		t.Fatalf("record should survive receiver delete attempt: %v", err)
	}

	// Owner delete succeeds.
	delOwner := newFakeSession(nil)
	_ = handleDelete(ctx, delOwner, store, ownerID, fileID)
	if delOwner.exitCode != exitOK {
		t.Fatalf("owner delete: exit=%d stderr=%q", delOwner.exitCode, delOwner.stderr.String())
	}
	// Now gone.
	dGone := newFakeSession(nil)
	_ = handleDownload(ctx, dGone, store, ownerID, fileID)
	if dGone.exitCode != exitNotFound {
		t.Fatalf("download after delete: exit=%d want not-found", dGone.exitCode)
	}
}

// TestUploadOverLimitNoRow verifies an oversized upload is rejected with
// "file too large" and commits no row.
func TestUploadOverLimitNoRow(t *testing.T) {
	store := newTestStore(t)
	store.SetMaxContentSize(64)
	ctx := context.Background()

	recvAddr, _ := testIdentity(t)
	_, ownerID := testIdentity(t)

	oversized := bytes.Repeat([]byte("A"), 200)
	up := newFakeSession(oversized)
	// Handler cap and store cap both bound the read; pass the store cap.
	_ = handleUpload(ctx, up, store, ownerID, []string{"-to", recvAddr}, 64)

	if up.exitCode != exitTooLarge {
		t.Fatalf("exit=%d want %d; stderr=%q", up.exitCode, exitTooLarge, up.stderr.String())
	}
	if strings.TrimSpace(up.stderr.String()) != tooLargeMessage {
		t.Fatalf("stderr=%q want %q", up.stderr.String(), tooLargeMessage)
	}
	if up.stdout.Len() != 0 {
		t.Fatalf("no id should be emitted; got %q", up.stdout.String())
	}

	// No row committed: the receiver should have no records.
	recvDecoded, err := identity.DecodeAddress(recvAddr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.ListReceived(ctx, recvDecoded.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no committed row, found %d", len(got))
	}
}

// TestSelfSendAllowed verifies owner==receiver uploads succeed (spec 6.2).
func TestSelfSendAllowed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := id.Address()
	if err != nil {
		t.Fatal(err)
	}
	self := id.UserID()

	up := newFakeSession([]byte("data"))
	_ = handleUpload(ctx, up, store, self, []string{"-to", addr}, storage.MaxContentSize)
	if up.exitCode != exitOK {
		t.Fatalf("self-send failed: exit=%d stderr=%q", up.exitCode, up.stderr.String())
	}
}

// TestUploadBadAddressInvalidArgs verifies a bad -to base58 is invalid args and
// reads nothing that commits a row.
func TestUploadBadAddressInvalidArgs(t *testing.T) {
	store := newTestStore(t)
	_, ownerID := testIdentity(t)

	up := newFakeSession([]byte("data"))
	_ = handleUpload(context.Background(), up, store, ownerID, []string{"-to", "0OIl-not-base58"}, storage.MaxContentSize)
	if up.exitCode != exitInvalid {
		t.Fatalf("exit=%d want %d", up.exitCode, exitInvalid)
	}
	if up.stdout.Len() != 0 {
		t.Fatal("no id should be emitted on invalid args")
	}
}
