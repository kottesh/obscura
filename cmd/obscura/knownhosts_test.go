package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// newTestHostKey returns a fresh Ed25519 SSH public key for host-key tests.
func newTestHostKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

// newRSAHostKey returns a non-Ed25519 SSH public key to exercise the type
// rejection in the TOFU callback.
func newRSAHostKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func TestNormalizeServer(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase host with port", "Relic-1:2222", "relic-1:2222"},
		{"already normalized", "relic-1:2222", "relic-1:2222"},
		{"whitespace trimmed", "  Relic-1:2222\t", "relic-1:2222"},
		{"uppercase host preserves port", "EXAMPLE.COM:22", "example.com:22"},
		{"ipv4 with port", "127.0.0.1:2222", "127.0.0.1:2222"},
		{"bare host no port lowercased", "Relic-1", "relic-1"},
		{"empty", "   ", ""},
		{"ipv6 with port", "[::1]:2222", "[::1]:2222"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeServer(tc.in); got != tc.want {
				t.Errorf("normalizeServer(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// The two spellings in the task must collapse to the same key.
	if normalizeServer("Relic-1:2222") != normalizeServer("relic-1:2222") {
		t.Error("Relic-1:2222 must normalize equal to relic-1:2222")
	}
}

func TestFingerprintSHA256(t *testing.T) {
	key := newTestHostKey(t)
	sum := sha256.Sum256(key.Marshal())
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	got := fingerprintSHA256(key)
	if got != want {
		t.Errorf("fingerprintSHA256 = %q, want %q", got, want)
	}
	if strings.HasSuffix(got, "=") {
		t.Errorf("fingerprint must be unpadded base64, got %q", got)
	}
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("fingerprint must start with SHA256:, got %q", got)
	}
}

func TestTOFUCallbackFirstUse(t *testing.T) {
	key := newTestHostKey(t)
	cb, res := tofuHostKeyCallback("relic-1:2222", nil)
	if err := cb("relic-1:2222", dummyAddr{}, key); err != nil {
		t.Fatalf("first-use callback should accept, got %v", err)
	}
	if !res.firstUse {
		t.Error("firstUse should be true on an absent-cache accept")
	}
	if res.key == nil || string(res.key.Marshal()) != string(key.Marshal()) {
		t.Error("firstUse should capture the presented key")
	}
}

func TestTOFUCallbackMatch(t *testing.T) {
	key := newTestHostKey(t)
	entries := []knownHostEntry{{server: "relic-1:2222", keyLine: hostKeyLine(key)}}
	cb, res := tofuHostKeyCallback("relic-1:2222", entries)
	if err := cb("relic-1:2222", dummyAddr{}, key); err != nil {
		t.Fatalf("matching callback should accept, got %v", err)
	}
	if res.firstUse {
		t.Error("firstUse must be false when the key already matches")
	}
}

func TestTOFUCallbackMismatch(t *testing.T) {
	cached := newTestHostKey(t)
	presented := newTestHostKey(t)
	entries := []knownHostEntry{{server: "relic-1:2222", keyLine: hostKeyLine(cached)}}
	cb, _ := tofuHostKeyCallback("relic-1:2222", entries)
	err := cb("relic-1:2222", dummyAddr{}, presented)
	if err == nil {
		t.Fatal("mismatched callback must return an error")
	}
	var che *changedHostKeyError
	if !errors.As(err, &che) {
		t.Fatalf("mismatch error type = %T, want *changedHostKeyError", err)
	}
	if che.cachedFP != fingerprintSHA256(cached) {
		t.Errorf("cached fingerprint = %q, want %q", che.cachedFP, fingerprintSHA256(cached))
	}
	if che.presentedFP != fingerprintSHA256(presented) {
		t.Errorf("presented fingerprint = %q, want %q", che.presentedFP, fingerprintSHA256(presented))
	}
	if !strings.Contains(err.Error(), che.cachedFP) || !strings.Contains(err.Error(), che.presentedFP) {
		t.Errorf("error text must carry both fingerprints: %q", err.Error())
	}
}

func TestTOFUCallbackRejectsNonEd25519(t *testing.T) {
	// An RSA key must be rejected regardless of cache state.
	rsaKey := newRSAHostKey(t)
	cb, _ := tofuHostKeyCallback("relic-1:2222", nil)
	if err := cb("relic-1:2222", dummyAddr{}, rsaKey); err == nil {
		t.Fatal("non-Ed25519 host key must be rejected")
	}
}

func TestKnownHostsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := newTestHostKey(t)

	// Absent file: empty load, no error.
	entries, err := loadKnownHosts(dir)
	if err != nil {
		t.Fatalf("loadKnownHosts on empty dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}

	// Record and reload.
	if err := recordKnownHost(dir, "relic-1:2222", hostKeyLine(key)); err != nil {
		t.Fatalf("recordKnownHost: %v", err)
	}
	entries, err = loadKnownHosts(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := lookupKnownHost(entries, "relic-1:2222")
	if !ok {
		t.Fatal("recorded server not found on reload")
	}
	if got.keyLine != hostKeyLine(key) {
		t.Errorf("key line mismatch: got %q", got.keyLine)
	}

	// File must be 0600 and dir 0700.
	fi, err := os.Stat(knownHostsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts perm = %o, want 600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Join(dir, appDir))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("appDir perm = %o, want 700", di.Mode().Perm())
	}

	// A second server is an independent entry; the first survives.
	key2 := newTestHostKey(t)
	if err := recordKnownHost(dir, "relic-2:2222", hostKeyLine(key2)); err != nil {
		t.Fatal(err)
	}
	entries, _ = loadKnownHosts(dir)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// forget removes only the named entry.
	removed, err := forgetKnownHost(dir, "relic-1:2222")
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("forget should report removed=true")
	}
	entries, _ = loadKnownHosts(dir)
	if _, ok := lookupKnownHost(entries, "relic-1:2222"); ok {
		t.Error("relic-1 should be gone after forget")
	}
	if _, ok := lookupKnownHost(entries, "relic-2:2222"); !ok {
		t.Error("relic-2 must survive forgetting relic-1")
	}

	// forgetting a missing entry reports removed=false, no error.
	removed, err = forgetKnownHost(dir, "nope:2222")
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Error("forgetting a missing entry must report removed=false")
	}
}

// dummyAddr is a net.Addr used to drive the host-key callback in unit tests.
type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:2222" }

var _ net.Addr = dummyAddr{}
