package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/sshsrv"
	"github.com/kottesh/obscura/internal/storage"
)

// startServer starts an in-process sshsrv.Server on an ephemeral localhost port
// with a temp SQLite store and an ephemeral Ed25519 host key added via
// AddHostKey. It returns the listen address, the store, and the server's host
// public key so the client can pin it. All state (DB, host key) lives in
// t.TempDir()/in-memory; nothing is written to the package dir or CWD.
func startServer(t *testing.T) (addr string, store *storage.SQLiteStore, hostPub gossh.PublicKey) {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "obscura-client-test.db")
	store, err := storage.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Ephemeral host key, added via AddHostKey (never persisted to disk).
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := sshsrv.NewServer(sshsrv.Config{
		Addr:        "127.0.0.1:0",
		Store:       store,
		MaxUpload:   1 << 20,
		IdleTimeout: 10 * time.Second,
		MaxTimeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String(), store, hostSigner.PublicKey()
}

// newIdentity returns a fresh Obscura identity for a test principal.
func newIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestClientEndToEnd exercises the full protocol against a live in-process
// server: Upload -> List (received/sent) -> Download (byte-exact) -> Delete ->
// Download-again (ErrNotFound), using distinct sender and receiver identities,
// plus a third identity that must see ErrNotFound.
func TestClientEndToEnd(t *testing.T) {
	addr, store, hostPub := startServer(t)
	_ = store

	sender := newIdentity(t)
	receiver := newIdentity(t)
	third := newIdentity(t)

	recvAddr, err := receiver.Address()
	if err != nil {
		t.Fatal(err)
	}

	// Pin the server host key (known-hosts style). InsecureIgnoreHostKey is
	// avoided here in favor of the real pin so the test also covers host
	// verification.
	hostCB := gossh.FixedHostKey(hostPub)

	senderClient, err := New(addr, sender.SignPriv, hostCB)
	if err != nil {
		t.Fatalf("New sender: %v", err)
	}
	senderClient.SetDialTimeout(5 * time.Second)

	receiverClient, err := New(addr, receiver.SignPriv, hostCB)
	if err != nil {
		t.Fatalf("New receiver: %v", err)
	}
	thirdClient, err := New(addr, third.SignPriv, hostCB)
	if err != nil {
		t.Fatalf("New third: %v", err)
	}

	ctx := context.Background()

	// Binary payload with NUL and high bytes to prove byte-exact round trip.
	content := []byte("byte-exact\x00\x01\x02\xff\xfeencrypted payload")

	// Upload as sender to receiver, with a name and explicit carrier.
	fileID, err := senderClient.Upload(ctx, bytes.NewReader(content), recvAddr, "doc.pkg", "package")
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if fileID == "" {
		t.Fatal("Upload returned empty file id")
	}

	// The stored record must bind the sender-derived owner id and receiver id.
	rec, err := store.Find(ctx, fileID)
	if err != nil {
		t.Fatalf("store.Find: %v", err)
	}
	if rec.OwnerUserID != sender.UserID() {
		t.Error("owner id does not match sender")
	}
	if rec.ReceiverUserID != receiver.UserID() {
		t.Error("receiver id does not match receiver")
	}
	if rec.DisplayName != "doc.pkg" || rec.CarrierType != storage.PackageCarrier {
		t.Errorf("record metadata = name %q carrier %q", rec.DisplayName, rec.CarrierType)
	}

	// List as sender with -sent: the row must be present and parsed correctly.
	sentRows, err := senderClient.List(ctx, "sent")
	if err != nil {
		t.Fatalf("List sent: %v", err)
	}
	sentRow := findRow(sentRows, fileID)
	if sentRow == nil {
		t.Fatalf("uploaded id %q not in sender's -sent listing: %+v", fileID, sentRows)
	}
	if sentRow.Direction != "sent" || sentRow.Carrier != "package" || sentRow.Name != "doc.pkg" {
		t.Errorf("sent row parsed wrong: %+v", *sentRow)
	}
	if sentRow.Size != uint64(len(content)) {
		t.Errorf("sent row size = %d, want %d", sentRow.Size, len(content))
	}

	// List as receiver with -received: same id, direction recv.
	recvRows, err := receiverClient.List(ctx, "received")
	if err != nil {
		t.Fatalf("List received: %v", err)
	}
	recvRow := findRow(recvRows, fileID)
	if recvRow == nil {
		t.Fatalf("uploaded id %q not in receiver's -received listing: %+v", fileID, recvRows)
	}
	if recvRow.Direction != "recv" {
		t.Errorf("received row direction = %q, want recv", recvRow.Direction)
	}

	// Default list (no filter) as receiver should also include the id.
	allRows, err := receiverClient.List(ctx, "")
	if err != nil {
		t.Fatalf("List default: %v", err)
	}
	if findRow(allRows, fileID) == nil {
		t.Errorf("id %q not in receiver's default listing", fileID)
	}

	// Download as receiver: bytes must be byte-identical to the upload.
	var dl bytes.Buffer
	if err := receiverClient.Download(ctx, fileID, &dl); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(dl.Bytes(), content) {
		t.Fatalf("download bytes not exact:\n got %q\nwant %q", dl.Bytes(), content)
	}

	// Download as sender (owner) must also succeed and be byte-exact.
	var dlOwner bytes.Buffer
	if err := senderClient.Download(ctx, fileID, &dlOwner); err != nil {
		t.Fatalf("owner Download: %v", err)
	}
	if !bytes.Equal(dlOwner.Bytes(), content) {
		t.Fatal("owner download bytes not exact")
	}

	// A third party must see ErrNotFound (unauthorized folds into not-found).
	var thirdBuf bytes.Buffer
	if err := thirdClient.Download(ctx, fileID, &thirdBuf); !errors.Is(err, ErrNotFound) {
		t.Fatalf("third-party Download error = %v, want ErrNotFound", err)
	}

	// A third party cannot delete either (owner-only; folds into not-found).
	if err := thirdClient.Delete(ctx, fileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("third-party Delete error = %v, want ErrNotFound", err)
	}
	// A receiver cannot delete the owner's copy.
	if err := receiverClient.Delete(ctx, fileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("receiver Delete error = %v, want ErrNotFound", err)
	}

	// Delete as owner (sender) succeeds.
	if err := senderClient.Delete(ctx, fileID); err != nil {
		t.Fatalf("owner Delete: %v", err)
	}
	if _, err := store.Find(ctx, fileID); err == nil {
		t.Fatal("record should be gone after delete")
	}

	// Download again after delete: ErrNotFound.
	var afterDelete bytes.Buffer
	if err := receiverClient.Download(ctx, fileID, &afterDelete); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-delete Download error = %v, want ErrNotFound", err)
	}
}

// TestClientDownloadMissing verifies a well-formed but unknown id returns
// ErrNotFound rather than a generic remote error.
func TestClientDownloadMissing(t *testing.T) {
	addr, _, hostPub := startServer(t)
	id := newIdentity(t)

	client, err := New(addr, id.SignPriv, gossh.FixedHostKey(hostPub))
	if err != nil {
		t.Fatal(err)
	}

	// 16-char id from the storage alphabet, but never uploaded.
	var buf bytes.Buffer
	err = client.Download(context.Background(), "aaaaaaaaaaaaaaaa", &buf)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Download missing = %v, want ErrNotFound", err)
	}
}

// TestClientUploadInvalidAddress verifies an invalid -to address surfaces as a
// RemoteError (invalid arguments), not a typed not-found/too-large error.
func TestClientUploadInvalidAddress(t *testing.T) {
	addr, _, hostPub := startServer(t)
	id := newIdentity(t)

	client, err := New(addr, id.SignPriv, gossh.FixedHostKey(hostPub))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Upload(context.Background(), bytes.NewReader([]byte("x")), "not-a-valid-address", "", "")
	var re *RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("Upload invalid address = %v, want *RemoteError", err)
	}
	if re.ExitCode != exitInvalid {
		t.Errorf("exit code = %d, want %d", re.ExitCode, exitInvalid)
	}
}

// TestNewValidatesArgs checks constructor rejection of bad inputs.
func TestNewValidatesArgs(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cb := gossh.InsecureIgnoreHostKey() // test-only; see New doc.

	if _, err := New("", priv, cb); err == nil {
		t.Error("empty addr should error")
	}
	if _, err := New("host:22", ed25519.PrivateKey{1, 2, 3}, cb); err == nil {
		t.Error("short key should error")
	}
	if _, err := New("host:22", priv, nil); err == nil {
		t.Error("nil host key callback should error")
	}
}

// findRow returns the row with the given id, or nil.
func findRow(rows []ListRow, id string) *ListRow {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}
