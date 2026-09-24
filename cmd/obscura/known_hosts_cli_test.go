package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/kottesh/obscura/internal/sshsrv"
	"github.com/kottesh/obscura/internal/storage"
)

// tofuServer starts an in-process Obscura SSH server on a FIXED localhost
// address so a second server can later reuse the exact same dial string with a
// DIFFERENT host key (to simulate a key rotation / MITM). It returns the
// address and the authorized_keys-style host key line. All state lives under
// t.TempDir()/in-memory.
func tofuServer(t *testing.T, hostSigner gossh.Signer) (addr string, stop func()) {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "obscura-tofu-test.db")
	store, err := storage.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
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

	stop = func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = store.Close()
	}
	return ln.Addr().String(), stop
}

// newHostSigner returns a fresh Ed25519 host signer.
func newHostSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// runTOFU invokes run() with NO host key configured so the CLI uses the TOFU
// cache under configDir.
func runTOFU(t *testing.T, server, configDir string, stdin []byte, args ...string) cliResult {
	t.Helper()
	env := map[string]string{"OBSCURA_SERVER": server}
	getenv := func(k string) string { return env[k] }

	full := append([]string{"--config-dir", configDir}, args...)
	var out, errb bytes.Buffer
	code := run(context.Background(), full, bytes.NewReader(stdin), &out, &errb, getenv)
	return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
}

// TestTOFURecordsAfterDial drives the CLI with NO host_key configured. The first
// `list` records the server's key into <config-dir>/obscura/known_hosts (0600,
// correct key), a first-use notice lands on stderr only, and a second run
// against the SAME key succeeds. Then a DIFFERENT server key on the same address
// fails with a changed-key error and does NOT overwrite the cache.
func TestTOFURecordsAfterDial(t *testing.T) {
	signer := newHostSigner(t)
	addr, stop := tofuServer(t, signer)

	// init needs an identity; supply no host key (TOFU).
	dir := t.TempDir()
	if r := runTOFU(t, addr, dir, nil, "init"); r.code != exitOK {
		t.Fatalf("init exit=%d stderr=%s", r.code, r.stderr)
	}

	// No cache yet.
	if _, err := os.Stat(knownHostsPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("known_hosts must not exist before first connect: %v", err)
	}

	// First list: records the key, emits a first-use notice to stderr.
	first := runTOFU(t, addr, dir, nil, "list")
	if first.code != exitOK {
		t.Fatalf("first list exit=%d stderr=%s", first.code, first.stderr)
	}
	wantFP := fingerprintSHA256(signer.PublicKey())
	if !strings.Contains(first.stderr, wantFP) {
		t.Errorf("first-use notice missing fingerprint %q in stderr:\n%s", wantFP, first.stderr)
	}
	if strings.Contains(first.stdout, wantFP) {
		t.Error("first-use notice must not leak to stdout")
	}

	// Cache file exists, 0600, and holds the correct key.
	fi, err := os.Stat(knownHostsPath(dir))
	if err != nil {
		t.Fatalf("known_hosts must exist after first connect: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts perm = %o, want 600", fi.Mode().Perm())
	}
	entries, err := loadKnownHosts(dir)
	if err != nil {
		t.Fatal(err)
	}
	norm := normalizeServer(addr)
	got, ok := lookupKnownHost(entries, norm)
	if !ok {
		t.Fatalf("server %q not recorded; entries=%+v", norm, entries)
	}
	if got.keyLine != hostKeyLine(signer.PublicKey()) {
		t.Errorf("recorded key line mismatch")
	}

	// Second list against the same key: succeeds, no new first-use notice.
	second := runTOFU(t, addr, dir, nil, "list")
	if second.code != exitOK {
		t.Fatalf("second list exit=%d stderr=%s", second.code, second.stderr)
	}
	if strings.Contains(second.stderr, "first use") {
		t.Error("second connect must not re-emit a first-use notice")
	}

	stop()

	// Start a DIFFERENT server (new host key) on the SAME address string.
	signer2 := newHostSigner(t)
	if err := reuseListen(t, addr, signer2); err != nil {
		t.Fatalf("reuse listener: %v", err)
	}

	changed := runTOFU(t, addr, dir, nil, "list")
	if changed.code == exitOK {
		t.Fatal("changed host key must fail the connection")
	}
	if changed.stdout != "" {
		t.Errorf("changed-key run stdout must be empty, got %q", changed.stdout)
	}
	if !strings.Contains(changed.stderr, "CHANGED") {
		t.Errorf("changed-key stderr must state the key CHANGED:\n%s", changed.stderr)
	}
	if !strings.Contains(changed.stderr, "known-hosts forget") {
		t.Errorf("changed-key stderr must instruct to run known-hosts forget:\n%s", changed.stderr)
	}
	// Cache must NOT be overwritten: original key still present.
	entries2, _ := loadKnownHosts(dir)
	got2, _ := lookupKnownHost(entries2, norm)
	if got2.keyLine != hostKeyLine(signer.PublicKey()) {
		t.Error("cache must NOT be overwritten on a changed-key failure")
	}
}

// TestTOFUFirstUseNoticeSuppressedInQuiet verifies that --quiet suppresses the
// first-use pin notice on stderr while STILL recording the pin (the notice is
// progress, not an error). --json suppression is covered by the JSON discipline
// tests; here we focus on quiet.
func TestTOFUFirstUseNoticeSuppressedInQuiet(t *testing.T) {
	signer := newHostSigner(t)
	addr, stop := tofuServer(t, signer)
	defer stop()

	dir := t.TempDir()
	if r := runTOFU(t, addr, dir, nil, "init"); r.code != exitOK {
		t.Fatalf("init exit=%d stderr=%s", r.code, r.stderr)
	}

	// First list under --quiet: no first-use notice anywhere, but the pin is
	// still recorded.
	res := runTOFU(t, addr, dir, nil, "--quiet", "list")
	if res.code != exitOK {
		t.Fatalf("quiet list exit=%d stderr=%s", res.code, res.stderr)
	}
	wantFP := fingerprintSHA256(signer.PublicKey())
	if strings.Contains(res.stderr, wantFP) || strings.Contains(res.stderr, "first use") {
		t.Errorf("--quiet must suppress the first-use notice; stderr:\n%s", res.stderr)
	}
	if strings.Contains(res.stdout, wantFP) {
		t.Error("first-use notice must never reach stdout")
	}

	// The pin was still recorded despite the suppressed notice.
	entries, err := loadKnownHosts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lookupKnownHost(entries, normalizeServer(addr)); !ok {
		t.Fatal("--quiet first use must still record the host key")
	}
}

// reuseListen starts a new server bound to the exact addr with a new host key.
// The previous server on addr must already be closed.
func reuseListen(t *testing.T, addr string, signer gossh.Signer) error {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "obscura-tofu-reuse.db")
	store, err := storage.Open(context.Background(), dsn)
	if err != nil {
		return err
	}
	srv, err := sshsrv.NewServer(sshsrv.Config{
		Addr:        addr,
		Store:       store,
		MaxUpload:   1 << 20,
		IdleTimeout: 10 * time.Second,
		MaxTimeout:  30 * time.Second,
	})
	if err != nil {
		return err
	}
	srv.AddHostKey(signer)

	var ln net.Listener
	// The OS may hold the port briefly after Close; retry a few times.
	for i := 0; i < 50; i++ {
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = store.Close()
	})
	return nil
}

// TestTOFUForgetReTOFUs verifies known-hosts list shows the entry, forget
// removes it, and a subsequent connect re-pins (records again).
func TestTOFUForgetReTOFUs(t *testing.T) {
	signer := newHostSigner(t)
	addr, stop := tofuServer(t, signer)
	t.Cleanup(stop)

	dir := t.TempDir()
	if r := runTOFU(t, addr, dir, nil, "init"); r.code != exitOK {
		t.Fatalf("init: %s", r.stderr)
	}
	if r := runTOFU(t, addr, dir, nil, "list"); r.code != exitOK {
		t.Fatalf("first list: %s", r.stderr)
	}

	norm := normalizeServer(addr)
	wantFP := fingerprintSHA256(signer.PublicKey())

	// known-hosts list shows the entry (server + fingerprint) on stdout.
	khList := runTOFU(t, addr, dir, nil, "known-hosts", "list")
	if khList.code != exitOK {
		t.Fatalf("known-hosts list exit=%d stderr=%s", khList.code, khList.stderr)
	}
	if !strings.Contains(khList.stdout, norm) || !strings.Contains(khList.stdout, wantFP) {
		t.Errorf("known-hosts list stdout missing server/fingerprint:\n%s", khList.stdout)
	}

	// --json known-hosts list emits one JSON object.
	khJSON := runTOFU(t, addr, dir, nil, "--json", "known-hosts", "list")
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(khJSON.stdout))
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("known-hosts list --json not one object: %v (%q)", err, khJSON.stdout)
	}
	if dec.More() {
		t.Error("known-hosts list --json emitted more than one value")
	}

	// forget removes the entry.
	forget := runTOFU(t, addr, dir, nil, "known-hosts", "forget", addr)
	if forget.code != exitOK {
		t.Fatalf("forget exit=%d stderr=%s", forget.code, forget.stderr)
	}
	if forget.stdout != "" {
		t.Errorf("forget stdout must be empty in normal mode, got %q", forget.stdout)
	}
	entries, _ := loadKnownHosts(dir)
	if _, ok := lookupKnownHost(entries, norm); ok {
		t.Error("entry must be gone after forget")
	}

	// A subsequent connect re-pins (records again + first-use notice).
	reconnect := runTOFU(t, addr, dir, nil, "list")
	if reconnect.code != exitOK {
		t.Fatalf("re-connect exit=%d stderr=%s", reconnect.code, reconnect.stderr)
	}
	if !strings.Contains(reconnect.stderr, wantFP) {
		t.Errorf("re-TOFU must re-emit first-use notice:\n%s", reconnect.stderr)
	}
	entries2, _ := loadKnownHosts(dir)
	if _, ok := lookupKnownHost(entries2, norm); !ok {
		t.Error("entry must be recorded again after re-connect")
	}

	// forgetting a missing entry is a clear non-zero error.
	miss := runTOFU(t, addr, dir, nil, "known-hosts", "forget", "no-such-host:2222")
	if miss.code == exitOK {
		t.Error("forgetting a missing entry must be non-zero")
	}
}

// TestTOFUChangedKeyJSON verifies that in --json mode a changed host key yields
// an empty-of-listing... actually a single JSON error object on stdout and a
// non-zero exit, with stdout carrying exactly one JSON value.
func TestTOFUChangedKeyWrongCache(t *testing.T) {
	signer := newHostSigner(t)
	addr, stop := tofuServer(t, signer)
	t.Cleanup(stop)

	dir := t.TempDir()
	if r := runTOFU(t, addr, dir, nil, "init"); r.code != exitOK {
		t.Fatalf("init: %s", r.stderr)
	}

	// Craft a cache with a WRONG key for this server.
	wrong := newHostSigner(t)
	if err := recordKnownHost(dir, normalizeServer(addr), hostKeyLine(wrong.PublicKey())); err != nil {
		t.Fatal(err)
	}

	res := runTOFU(t, addr, dir, nil, "list")
	if res.code == exitOK {
		t.Fatal("wrong cached key must fail")
	}
	if res.stdout != "" {
		t.Errorf("changed-key stdout must be empty, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, fingerprintSHA256(wrong.PublicKey())) {
		t.Errorf("stderr must show cached fingerprint")
	}
	if !strings.Contains(res.stderr, fingerprintSHA256(signer.PublicKey())) {
		t.Errorf("stderr must show presented fingerprint")
	}
	// Cache NOT overwritten: still the wrong key.
	entries, _ := loadKnownHosts(dir)
	got, _ := lookupKnownHost(entries, normalizeServer(addr))
	if got.keyLine != hostKeyLine(wrong.PublicKey()) {
		t.Error("cache must not be overwritten on mismatch")
	}
}

// TestExplicitPinNoCache verifies an explicit host_key still hard-pins and does
// NOT create a known_hosts entry; a wrong explicit pin fails.
func TestExplicitPinNoCache(t *testing.T) {
	signer := newHostSigner(t)
	addr, stop := tofuServer(t, signer)
	t.Cleanup(stop)

	correctLine := hostKeyLine(signer.PublicKey())
	dir := t.TempDir()

	// init and list with an EXPLICIT correct pin via env.
	env := map[string]string{"OBSCURA_SERVER": addr, "OBSCURA_HOST_KEY": correctLine}
	getenv := func(k string) string { return env[k] }
	runExplicit := func(args ...string) cliResult {
		full := append([]string{"--config-dir", dir}, args...)
		var out, errb bytes.Buffer
		code := run(context.Background(), full, bytes.NewReader(nil), &out, &errb, getenv)
		return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
	}

	if r := runExplicit("init"); r.code != exitOK {
		t.Fatalf("init: %s", r.stderr)
	}
	if r := runExplicit("list"); r.code != exitOK {
		t.Fatalf("explicit-pin list exit=%d stderr=%s", r.code, r.stderr)
	}
	// No TOFU cache must have been created.
	if _, err := os.Stat(knownHostsPath(dir)); !os.IsNotExist(err) {
		t.Errorf("explicit pin must NOT create known_hosts: %v", err)
	}

	// A WRONG explicit pin fails.
	wrong := newHostSigner(t)
	env["OBSCURA_HOST_KEY"] = hostKeyLine(wrong.PublicKey())
	if r := runExplicit("list"); r.code == exitOK {
		t.Fatal("wrong explicit pin must fail")
	}
	if _, err := os.Stat(knownHostsPath(dir)); !os.IsNotExist(err) {
		t.Errorf("a failed explicit pin must NOT create known_hosts: %v", err)
	}
}
