package sshsrv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/storage"
)

// startTestServer starts a Server on an ephemeral port with a fresh temp store
// and returns the listen address plus the store for assertions.
func startTestServer(t *testing.T) (addr string, store *storage.SQLiteStore, hostPub gossh.PublicKey) {
	t.Helper()
	store = newTestStore(t)

	// Ephemeral host key.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(Config{
		Addr:        "127.0.0.1:0",
		Store:       store,
		MaxUpload:   1 << 20,
		IdleTimeout: 10 * time.Second,
		MaxTimeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
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

// dialClient dials the server as the given ed25519 identity and returns a
// session-ready client.
func dialClient(t *testing.T, addr, user string, priv ed25519.PrivateKey, hostPub gossh.PublicKey) *gossh.Client {
	t.Helper()
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	}
	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// runExec runs one exec command over a fresh session and returns stdout, the
// combined stderr, and the exit code.
func runExec(t *testing.T, client *gossh.Client, command string, stdin []byte) (stdout []byte, stderr string, exitCode int) {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}

	err = sess.Run(command)
	if err != nil {
		var ee *gossh.ExitError
		if ok := asExitError(err, &ee); ok {
			exitCode = ee.ExitStatus()
		} else {
			t.Fatalf("run %q: %v", command, err)
		}
	}
	return outBuf.Bytes(), errBuf.String(), exitCode
}

func asExitError(err error, target **gossh.ExitError) bool {
	if ee, ok := err.(*gossh.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func genEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestServerEndToEnd runs upload/list/download/delete over a real SSH client,
// verifying identity derivation, byte-exact binary stdout, and stream
// separation end to end.
func TestServerEndToEnd(t *testing.T) {
	addr, store, hostPub := startTestServer(t)
	_ = store

	// Owner identity (SSH key = signing key); receiver identity for -to.
	ownerPub, ownerPriv := genEd25519(t)
	ownerID := identity.UserIDFromSignPub(ownerPub)

	recvIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recvAddr, err := recvIdent.Address()
	if err != nil {
		t.Fatal(err)
	}

	ownerClient := dialClient(t, addr, "upload", ownerPriv, hostPub)

	content := []byte("byte-exact\x00\x01\x02encrypted payload")

	// Upload.
	out, errOut, code := runExec(t, ownerClient, "-to "+recvAddr+" -name doc.pkg", content)
	if code != exitOK {
		t.Fatalf("upload exit=%d stderr=%q", code, errOut)
	}
	fileID := strings.TrimSpace(string(out))
	if !validFileID(fileID) {
		t.Fatalf("upload id invalid: %q", fileID)
	}

	// The stored record binds ownerID derived server-side from the SSH key.
	rec, err := store.Find(context.Background(), fileID)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if rec.OwnerUserID != ownerID {
		t.Fatal("server-derived owner id does not match SSH key")
	}
	if rec.DisplayName != "doc.pkg" {
		t.Fatalf("name=%q", rec.DisplayName)
	}

	// Download via f:<id> as the owner; binary stdout must be byte-exact and
	// stderr empty.
	dlClient := dialClient(t, addr, "f:"+fileID, ownerPriv, hostPub)
	dout, derr, dcode := runExec(t, dlClient, "", nil)
	if dcode != exitOK {
		t.Fatalf("download exit=%d stderr=%q", dcode, derr)
	}
	if !bytes.Equal(dout, content) {
		t.Fatalf("download bytes not exact: got %q", dout)
	}
	if derr != "" {
		t.Fatalf("download stderr should be empty, got %q", derr)
	}

	// list -sent contains the id.
	lout, _, lcode := runExec(t, ownerClient, "list -sent", nil)
	if lcode != exitOK || !strings.Contains(string(lout), fileID) {
		t.Fatalf("list -sent: code=%d out=%q", lcode, lout)
	}

	// Delete as owner.
	_, _, rmcode := runExec(t, dialClient(t, addr, "f:"+fileID, ownerPriv, hostPub), "rm", nil)
	if rmcode != exitOK {
		t.Fatalf("delete exit=%d", rmcode)
	}
	if _, err := store.Find(context.Background(), fileID); err == nil {
		t.Fatal("record should be gone after delete")
	}
}

// TestServerRejectsNonEd25519 verifies RSA keys cannot authenticate.
func TestServerRejectsNonEd25519(t *testing.T) {
	addr, _, hostPub := startTestServer(t)

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gossh.ClientConfig{
		User:            "upload",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	}
	client, err := gossh.Dial("tcp", addr, cfg)
	if err == nil {
		_ = client.Close()
		t.Fatal("RSA key should be rejected at auth")
	}
}

// TestServerNoPty verifies PTY requests are denied (lockdown).
func TestServerNoPty(t *testing.T) {
	addr, _, hostPub := startTestServer(t)
	_, priv := genEd25519(t)
	client := dialClient(t, addr, "upload", priv, hostPub)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()

	if err := sess.RequestPty("xterm", 40, 80, gossh.TerminalModes{}); err == nil {
		t.Fatal("PTY allocation should be denied")
	}
}

// TestServerThirdPartyNotFound verifies a third party sees the same not-found
// result as a missing id over the wire.
func TestServerThirdPartyNotFound(t *testing.T) {
	addr, _, hostPub := startTestServer(t)

	_, ownerPriv := genEd25519(t)
	_, thirdPriv := genEd25519(t)

	recvIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recvAddr, err := recvIdent.Address()
	if err != nil {
		t.Fatal(err)
	}

	ownerClient := dialClient(t, addr, "upload", ownerPriv, hostPub)
	out, _, code := runExec(t, ownerClient, "-to "+recvAddr, []byte("data"))
	if code != exitOK {
		t.Fatalf("upload failed: %d", code)
	}
	fileID := strings.TrimSpace(string(out))

	// Third party download of the real id.
	thirdClient := dialClient(t, addr, "f:"+fileID, thirdPriv, hostPub)
	_, e1, c1 := runExec(t, thirdClient, "", nil)

	// Third party download of a well-formed but missing id.
	missing := strings.Repeat("a", fileIDLength)
	missClient := dialClient(t, addr, "f:"+missing, thirdPriv, hostPub)
	_, e2, c2 := runExec(t, missClient, "", nil)

	if c1 != c2 || strings.TrimSpace(e1) != strings.TrimSpace(e2) {
		t.Fatalf("unauthorized vs missing differ: (%d,%q) vs (%d,%q)", c1, e1, c2, e2)
	}
	if strings.TrimSpace(e1) != notFoundMessage {
		t.Fatalf("stderr=%q want %q", e1, notFoundMessage)
	}
}
