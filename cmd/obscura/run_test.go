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
	"regexp"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/pkgfmt"
	"github.com/kottesh/obscura/internal/sshsrv"
	"github.com/kottesh/obscura/internal/storage"
)

// ansiPattern matches any ANSI escape sequence so tests can assert that stdout
// (and JSON output) carry no terminal decoration (spec 8.3/8.4).
var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

// testServer starts an in-process Obscura SSH server on an ephemeral localhost
// port with a temp SQLite store and an ephemeral Ed25519 host key. It returns
// the listen address and the host key as an authorized_keys-style line suitable
// for the CLI's --host-key flag. All state lives under t.TempDir()/in-memory.
func testServer(t *testing.T) (addr, hostKeyLine string) {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "obscura-cli-test.db")
	store, err := storage.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

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

	line := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	return ln.Addr().String(), line
}

// cliResult captures the outcome of one run() invocation.
type cliResult struct {
	code   int
	stdout string
	stderr string
}

// runCLI invokes run() with the given args and a fixed environment mapping for
// server/host-key so tests exercise the real flag+env plumbing. configDir and
// mode flags are supplied by the caller via args.
func runCLI(t *testing.T, server, hostKey string, stdin []byte, args ...string) cliResult {
	t.Helper()
	env := map[string]string{
		"OBSCURA_SERVER":   server,
		"OBSCURA_HOST_KEY": hostKey,
	}
	getenv := func(k string) string { return env[k] }

	var out, errb bytes.Buffer
	code := run(context.Background(), args, bytes.NewReader(stdin), &out, &errb, getenv)
	return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
}

// initIdentity runs 'obscura init' in a temp config dir and returns the config
// dir and the printed address.
func initIdentity(t *testing.T, server, hostKey string) (configDir, address string) {
	t.Helper()
	configDir = t.TempDir()
	res := runCLI(t, server, hostKey, nil, "--config-dir", configDir, "init")
	if res.code != exitOK {
		t.Fatalf("init exit=%d stderr=%s", res.code, res.stderr)
	}
	address = strings.TrimSpace(res.stdout)
	if address == "" {
		t.Fatalf("init printed empty address; stderr=%s", res.stderr)
	}
	return configDir, address
}

// TestRunEndToEnd drives the full CLI surface against a live server: init for
// two users, address, send A->B, list --received as B, receive as B (byte
// identical), delete as A, then receive again (not found).
func TestRunEndToEnd(t *testing.T) {
	server, hostKey := testServer(t)

	dirA, _ := initIdentity(t, server, hostKey)
	dirB, addrB := initIdentity(t, server, hostKey)

	// address for A must be non-empty and stable across calls.
	res := runCLI(t, server, hostKey, nil, "--config-dir", dirA, "address")
	if res.code != exitOK {
		t.Fatalf("address exit=%d stderr=%s", res.code, res.stderr)
	}
	if strings.TrimSpace(res.stdout) == "" {
		t.Fatal("address stdout empty")
	}
	if ansiPattern.MatchString(res.stdout) {
		t.Errorf("address stdout has ANSI escapes: %q", res.stdout)
	}

	// Create a source file with binary content to prove byte-exact round trip.
	content := []byte("obscura round-trip\x00\x01\x02\xff\xfe payload bytes")
	src := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	// send A -> B.
	sendRes := runCLI(t, server, hostKey, nil,
		"--config-dir", dirA, "send", src, "--to", addrB, "--name", "source.bin")
	if sendRes.code != exitOK {
		t.Fatalf("send exit=%d stderr=%s", sendRes.code, sendRes.stderr)
	}
	fileID := strings.TrimSpace(sendRes.stdout)
	if fileID == "" {
		t.Fatalf("send printed empty file id; stderr=%s", sendRes.stderr)
	}
	// stdout must contain ONLY the file id: no ANSI, no card glyphs.
	if ansiPattern.MatchString(sendRes.stdout) {
		t.Errorf("send stdout has ANSI escapes: %q", sendRes.stdout)
	}
	if strings.ContainsAny(sendRes.stdout, "┃") || sendRes.stdout != fileID+"\n" {
		t.Errorf("send stdout must be only the id; got %q", sendRes.stdout)
	}

	// list --received as B must include the file id.
	listRes := runCLI(t, server, hostKey, nil, "--config-dir", dirB, "list", "--received")
	if listRes.code != exitOK {
		t.Fatalf("list exit=%d stderr=%s", listRes.code, listRes.stderr)
	}
	if !strings.Contains(listRes.stdout, fileID) {
		t.Fatalf("list --received stdout missing id %q:\n%s", fileID, listRes.stdout)
	}
	if ansiPattern.MatchString(listRes.stdout) {
		t.Errorf("list stdout has ANSI escapes")
	}

	// receive as B to a -o path; stdout must be empty.
	outPath := filepath.Join(t.TempDir(), "recovered.bin")
	recvRes := runCLI(t, server, hostKey, nil, "--config-dir", dirB, "receive", fileID, "-o", outPath)
	if recvRes.code != exitOK {
		t.Fatalf("receive exit=%d stderr=%s", recvRes.code, recvRes.stderr)
	}
	if recvRes.stdout != "" {
		t.Errorf("receive -o stdout must be empty, got %q", recvRes.stdout)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("recovered bytes differ:\n got %q\nwant %q", got, content)
	}

	// delete as A (owner) succeeds.
	delRes := runCLI(t, server, hostKey, nil, "--config-dir", dirA, "delete", fileID)
	if delRes.code != exitOK {
		t.Fatalf("delete exit=%d stderr=%s", delRes.code, delRes.stderr)
	}

	// receive again -> not found, non-zero exit, empty stdout, error on stderr.
	recv2 := runCLI(t, server, hostKey, nil, "--config-dir", dirB, "receive", fileID, "-o", filepath.Join(t.TempDir(), "x.bin"))
	if recv2.code == exitOK {
		t.Fatal("receive after delete should fail")
	}
	if recv2.stdout != "" {
		t.Errorf("failed receive stdout must be empty, got %q", recv2.stdout)
	}
	if !strings.Contains(recv2.stderr, "file not found") {
		t.Errorf("failed receive stderr should mention 'file not found', got %q", recv2.stderr)
	}
}

// TestRunPNGRoundTrip proves send --png -> receive round-trips a file byte for
// byte through the PNG carrier.
func TestRunPNGRoundTrip(t *testing.T) {
	server, hostKey := testServer(t)

	dirA, _ := initIdentity(t, server, hostKey)
	dirB, addrB := initIdentity(t, server, hostKey)

	content := bytes.Repeat([]byte("png-carrier-payload\x00\xff"), 50)
	src := filepath.Join(t.TempDir(), "cover-source.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	sendRes := runCLI(t, server, hostKey, nil,
		"--config-dir", dirA, "send", src, "--to", addrB, "--png")
	if sendRes.code != exitOK {
		t.Fatalf("send --png exit=%d stderr=%s", sendRes.code, sendRes.stderr)
	}
	fileID := strings.TrimSpace(sendRes.stdout)
	if fileID == "" {
		t.Fatalf("send --png empty id; stderr=%s", sendRes.stderr)
	}

	outPath := filepath.Join(t.TempDir(), "png-recovered.bin")
	recvRes := runCLI(t, server, hostKey, nil, "--config-dir", dirB, "receive", fileID, "-o", outPath)
	if recvRes.code != exitOK {
		t.Fatalf("receive (png) exit=%d stderr=%s", recvRes.code, recvRes.stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("png round-trip bytes differ")
	}
}

// TestRunReceiveRaw verifies that receive --raw writes the stored bytes verbatim
// (the stego PNG here) without decrypting, so the output is the PNG carrier, not
// the plaintext.
func TestRunReceiveRaw(t *testing.T) {
	server, hostKey := testServer(t)

	dirA, _ := initIdentity(t, server, hostKey)
	dirB, addrB := initIdentity(t, server, hostKey)

	content := bytes.Repeat([]byte("raw-download-payload\x00\xff"), 40)
	src := filepath.Join(t.TempDir(), "raw-source.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	sendRes := runCLI(t, server, hostKey, nil,
		"--config-dir", dirA, "send", src, "--to", addrB, "--png")
	if sendRes.code != exitOK {
		t.Fatalf("send --png exit=%d stderr=%s", sendRes.code, sendRes.stderr)
	}
	fileID := strings.TrimSpace(sendRes.stdout)

	outPath := filepath.Join(t.TempDir(), "raw-download.bin")
	recvRes := runCLI(t, server, hostKey, nil,
		"--config-dir", dirB, "receive", fileID, "-o", outPath, "--raw")
	if recvRes.code != exitOK {
		t.Fatalf("receive --raw exit=%d stderr=%s", recvRes.code, recvRes.stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	// --raw returns the stored stego PNG, not the plaintext.
	if !bytes.HasPrefix(got, pngSignature) {
		t.Fatalf("raw output is not a PNG carrier (first bytes: %x)", got[:min(8, len(got))])
	}
	if bytes.Equal(got, content) {
		t.Fatal("raw output equals plaintext; it should be the encrypted carrier")
	}

	// The same file received normally (no --raw) must still recover the plaintext.
	plainPath := filepath.Join(t.TempDir(), "raw-recovered.bin")
	if r := runCLI(t, server, hostKey, nil,
		"--config-dir", dirB, "receive", fileID, "-o", plainPath); r.code != exitOK {
		t.Fatalf("normal receive after raw exit=%d stderr=%s", r.code, r.stderr)
	}
	plain, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, content) {
		t.Fatal("normal receive after raw did not recover plaintext")
	}
}

// TestRunReceiveToStdout verifies that receive with no -o writes byte-exact
// plaintext to stdout (non-TTY, simulated by a bytes.Buffer) with no card
// decoration mixed into the binary stream.
func TestRunReceiveToStdout(t *testing.T) {
	server, hostKey := testServer(t)

	dirA, _ := initIdentity(t, server, hostKey)
	dirB, addrB := initIdentity(t, server, hostKey)

	content := []byte("stdout-binary\x00\x01\x02\xff decorated? no")
	src := filepath.Join(t.TempDir(), "src.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	sendRes := runCLI(t, server, hostKey, nil, "--config-dir", dirA, "send", src, "--to", addrB)
	if sendRes.code != exitOK {
		t.Fatalf("send exit=%d stderr=%s", sendRes.code, sendRes.stderr)
	}
	fileID := strings.TrimSpace(sendRes.stdout)

	// receive with no -o: stdout is a bytes.Buffer (non-TTY) so bytes flow to it.
	recvRes := runCLI(t, server, hostKey, nil, "--config-dir", dirB, "receive", fileID)
	if recvRes.code != exitOK {
		t.Fatalf("receive to stdout exit=%d stderr=%s", recvRes.code, recvRes.stderr)
	}
	if recvRes.stdout != string(content) {
		t.Fatalf("stdout not byte-exact:\n got %q\nwant %q", recvRes.stdout, content)
	}
	if ansiPattern.MatchString(recvRes.stdout) {
		t.Errorf("binary stdout has ANSI escapes")
	}
}

// TestRunJSONDiscipline asserts JSON mode writes exactly one JSON object to
// stdout with no ANSI, and no cards land on stdout. It checks send and list.
func TestRunJSONDiscipline(t *testing.T) {
	server, hostKey := testServer(t)

	dirA, _ := initIdentity(t, server, hostKey)
	dirB, addrB := initIdentity(t, server, hostKey)

	content := []byte("json-mode payload")
	src := filepath.Join(t.TempDir(), "j.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	sendRes := runCLI(t, server, hostKey, nil, "--json", "--config-dir", dirA, "send", src, "--to", addrB)
	if sendRes.code != exitOK {
		t.Fatalf("json send exit=%d stderr=%s", sendRes.code, sendRes.stderr)
	}
	if ansiPattern.MatchString(sendRes.stdout) {
		t.Errorf("json send stdout has ANSI escapes")
	}
	if strings.ContainsAny(sendRes.stderr, "┃") {
		t.Errorf("json mode emitted cards to stderr: %q", sendRes.stderr)
	}
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(sendRes.stdout))
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("json send stdout is not one JSON object: %v (%q)", err, sendRes.stdout)
	}
	if dec.More() {
		t.Error("json send stdout has more than one JSON value")
	}
	fileID, _ := obj["file_id"].(string)
	if fileID == "" {
		t.Fatalf("json send missing file_id: %v", obj)
	}

	listRes := runCLI(t, server, hostKey, nil, "--json", "--config-dir", dirB, "list", "--received")
	if listRes.code != exitOK {
		t.Fatalf("json list exit=%d stderr=%s", listRes.code, listRes.stderr)
	}
	var listObj map[string]any
	ldec := json.NewDecoder(strings.NewReader(listRes.stdout))
	if err := ldec.Decode(&listObj); err != nil {
		t.Fatalf("json list stdout not one JSON object: %v (%q)", err, listRes.stdout)
	}
	if ldec.More() {
		t.Error("json list stdout has more than one JSON value")
	}
	if strings.ContainsAny(listRes.stderr, "┃") {
		t.Errorf("json list emitted cards to stderr")
	}
}

// TestRunReceiveNotFound checks the error mapping: an unknown id exits non-zero
// with "file not found" on stderr and an empty stdout.
func TestRunReceiveNotFound(t *testing.T) {
	server, hostKey := testServer(t)
	dirB, _ := initIdentity(t, server, hostKey)

	outPath := filepath.Join(t.TempDir(), "nf.bin")
	res := runCLI(t, server, hostKey, nil, "--config-dir", dirB, "receive", "aaaaaaaaaaaaaaaa", "-o", outPath)
	if res.code == exitOK {
		t.Fatal("receive of unknown id should be non-zero")
	}
	if res.stdout != "" {
		t.Errorf("not-found receive stdout must be empty, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "file not found") {
		t.Errorf("not-found stderr should mention 'file not found', got %q", res.stderr)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("not-found receive must not create the output file")
	}
}

// TestRunMissingIdentity verifies commands requiring an identity tell the user
// to run 'obscura init' and exit non-zero when no seed exists.
func TestRunMissingIdentity(t *testing.T) {
	server, hostKey := testServer(t)
	empty := t.TempDir()

	res := runCLI(t, server, hostKey, nil, "--config-dir", empty, "address")
	if res.code == exitOK {
		t.Fatal("address without identity should be non-zero")
	}
	if !strings.Contains(res.stderr, "obscura init") {
		t.Errorf("missing-identity stderr should point to 'obscura init', got %q", res.stderr)
	}
	if res.stdout != "" {
		t.Errorf("missing-identity stdout must be empty, got %q", res.stdout)
	}
}

// TestRunInitSeedOnStderrOnly verifies init prints the address to stdout and the
// recovery seed only to stderr (never stdout), and that --recover restores the
// same address.
func TestRunInitSeedOnStderrOnly(t *testing.T) {
	server, hostKey := testServer(t)
	dir := t.TempDir()

	res := runCLI(t, server, hostKey, nil, "--config-dir", dir, "init")
	if res.code != exitOK {
		t.Fatalf("init exit=%d stderr=%s", res.code, res.stderr)
	}
	address := strings.TrimSpace(res.stdout)
	// stdout must be exactly the address line; the seed must not appear there.
	if res.stdout != address+"\n" {
		t.Errorf("init stdout must be only the address, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "recovery seed") && !strings.Contains(res.stderr, "seed:") {
		t.Errorf("init stderr should surface the recovery seed note, got %q", res.stderr)
	}

	// Extract the seed from stderr and recover into a fresh dir; the address
	// must match, proving deterministic recovery.
	seed := extractSeed(t, res.stderr)
	dir2 := t.TempDir()
	rec := runCLI(t, server, hostKey, nil, "--config-dir", dir2, "init", "--recover", seed)
	if rec.code != exitOK {
		t.Fatalf("init --recover exit=%d stderr=%s", rec.code, rec.stderr)
	}
	if strings.TrimSpace(rec.stdout) != address {
		t.Fatalf("recovered address %q != original %q", strings.TrimSpace(rec.stdout), address)
	}

	// A second init without --force must refuse.
	again := runCLI(t, server, hostKey, nil, "--config-dir", dir, "init")
	if again.code == exitOK {
		t.Error("second init without --force should fail")
	}
}

// extractSeed pulls the base58 seed token out of the init stderr "seed: ..."
// note.
func extractSeed(t *testing.T, stderr string) string {
	t.Helper()
	for _, line := range strings.Split(stderr, "\n") {
		if i := strings.Index(line, "seed:"); i >= 0 {
			return strings.TrimSpace(line[i+len("seed:"):])
		}
	}
	t.Fatalf("no seed line found in stderr: %q", stderr)
	return ""
}

// TestRunInspect checks inspect prints non-secret metadata for a local package
func TestRunInspect(t *testing.T) {
	server, hostKey := testServer(t)
	dirA, _ := initIdentity(t, server, hostKey)
	_, addrB := initIdentity(t, server, hostKey)

	// inspect reads a local file and never contacts the server. Build a raw
	// package on disk by sealing to B's box public key with the same public
	// packages the send path uses, then inspect it.
	_ = dirA

	pkgBytes := sealForTest(t, addrB, []byte("inspect me"))
	pkgPath := filepath.Join(t.TempDir(), "pkg.obsc")
	if err := os.WriteFile(pkgPath, pkgBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, server, hostKey, nil, "inspect", pkgPath)
	if res.code != exitOK {
		t.Fatalf("inspect exit=%d stderr=%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "carrier: package") {
		t.Errorf("inspect stdout missing carrier: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "format_version: 1") {
		t.Errorf("inspect stdout missing format_version: %q", res.stdout)
	}
}

// sealForTest seals payload to the receiver identified by its base58 address,
// using the same public pkgfmt path the CLI uses, so tests can produce a raw
// package on disk for inspect.
func sealForTest(t *testing.T, address string, payload []byte) []byte {
	t.Helper()
	addr, err := identity.DecodeAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := pkgfmt.Seal(addr.BoxPub, payload)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

// TestReceiveDeleteDashLeadingID is a regression test for a file id that begins
// with '-' (the storage id alphabet includes '-'). Such an id must be treated
// as the positional file id, never parsed as an unknown flag. It drives
// cmdReceive and cmdDelete directly with a synthetic dash-leading id and
// asserts the id reaches the server (surfacing as ErrNotFound, not a usage
// error about an unknown flag).
func TestReceiveDeleteDashLeadingID(t *testing.T) {
	server, hostKey := testServer(t)
	dir, _ := initIdentity(t, server, hostKey)

	// A well-formed-length id from the storage alphabet that starts with '-'.
	const dashID = "-bcDEF0123456789"
	if len(dashID) != 16 {
		t.Fatalf("test id must be 16 chars, got %d", len(dashID))
	}

	// receive: the id must be treated as the positional, so the failure is a
	// "file not found" from the server, not a usage error about an unknown flag.
	outPath := filepath.Join(t.TempDir(), "dash.bin")
	recv := runCLI(t, server, hostKey, nil, "--config-dir", dir, "receive", dashID, "-o", outPath)
	if recv.code == exitOK {
		t.Fatal("receive of unknown dash-leading id should fail")
	}
	if strings.Contains(recv.stderr, "flag provided but not defined") ||
		strings.Contains(recv.stderr, "not defined") {
		t.Errorf("dash-leading id was parsed as a flag: %q", recv.stderr)
	}
	if !strings.Contains(recv.stderr, "file not found") {
		t.Errorf("receive dash-leading id stderr should be 'file not found', got %q", recv.stderr)
	}

	// The same id with -o BEFORE the id must also work (flag/positional order).
	recv2 := runCLI(t, server, hostKey, nil, "--config-dir", dir, "receive", "-o", outPath, dashID)
	if recv2.code == exitOK {
		t.Fatal("receive (flag-first) of unknown dash-leading id should fail")
	}
	if strings.Contains(recv2.stderr, "not defined") {
		t.Errorf("dash-leading id (flag-first) parsed as a flag: %q", recv2.stderr)
	}
	if !strings.Contains(recv2.stderr, "file not found") {
		t.Errorf("receive (flag-first) stderr should be 'file not found', got %q", recv2.stderr)
	}

	// delete: same treatment; a dash-leading id reaches the server as not-found.
	del := runCLI(t, server, hostKey, nil, "--config-dir", dir, "delete", dashID)
	if del.code == exitOK {
		t.Fatal("delete of unknown dash-leading id should fail")
	}
	if strings.Contains(del.stderr, "not defined") {
		t.Errorf("delete dash-leading id parsed as a flag: %q", del.stderr)
	}
	if !strings.Contains(del.stderr, "file not found") {
		t.Errorf("delete dash-leading id stderr should be 'file not found', got %q", del.stderr)
	}
}

// TestSendReceiveDeleteRoundTripDashID proves a dash-leading id produced by a
// real upload round-trips through receive and delete. It forces the send path
// to yield a dash-leading id by retrying uploads until one is produced, so the
// test exercises a genuine server-issued id, not only a synthetic one.
func TestSendReceiveDeleteRoundTripDashID(t *testing.T) {
	server, hostKey := testServer(t)
	dirA, _ := initIdentity(t, server, hostKey)
	dirB, addrB := initIdentity(t, server, hostKey)

	content := []byte("dash-id round trip\x00\xff")
	src := filepath.Join(t.TempDir(), "dash-src.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	// Upload repeatedly until the server issues a dash-leading id (~1/16 each).
	var fileID string
	for i := 0; i < 200; i++ {
		res := runCLI(t, server, hostKey, nil, "--config-dir", dirA, "send", src, "--to", addrB)
		if res.code != exitOK {
			t.Fatalf("send exit=%d stderr=%s", res.code, res.stderr)
		}
		id := strings.TrimSpace(res.stdout)
		if strings.HasPrefix(id, "-") {
			fileID = id
			break
		}
	}
	if fileID == "" {
		t.Skip("no dash-leading id produced in 200 uploads; skipping (statistically unlikely)")
	}

	// receive the dash-leading id: must recover the plaintext byte-exactly.
	outPath := filepath.Join(t.TempDir(), "dash-recovered.bin")
	recv := runCLI(t, server, hostKey, nil, "--config-dir", dirB, "receive", fileID, "-o", outPath)
	if recv.code != exitOK {
		t.Fatalf("receive dash id exit=%d stderr=%s", recv.code, recv.stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("dash-id round trip bytes differ:\n got %q\nwant %q", got, content)
	}

	// delete the dash-leading id as owner.
	del := runCLI(t, server, hostKey, nil, "--config-dir", dirA, "delete", fileID)
	if del.code != exitOK {
		t.Fatalf("delete dash id exit=%d stderr=%s", del.code, del.stderr)
	}
}
