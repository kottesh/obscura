package sshsrv

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/charmbracelet/ssh"
	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/storage"
)

// TestCallerUserIDCrossIdentity proves the server derives caller_user_id from
// the RAW 32-byte Ed25519 key, matching identity.UserIDFromSignPub. This fails
// if anyone hashes the SSH wire encoding instead of the raw key.
func TestCallerUserIDCrossIdentity(t *testing.T) {
	for i := 0; i < 8; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}

		// Wrap the raw ed25519 key as an ssh.PublicKey exactly as the SSH
		// library would present it after authentication.
		sshPub, err := gossh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("new ssh public key: %v", err)
		}

		got, err := callerUserID(ssh.PublicKey(sshPub))
		if err != nil {
			t.Fatalf("callerUserID: %v", err)
		}
		want := identity.UserIDFromSignPub(pub)
		if got != want {
			t.Fatalf("iter %d: caller id mismatch\n got=%x\nwant=%x", i, got, want)
		}

		// Guard: the raw-key id must NOT equal the id of the wire encoding.
		wireID := identity.UserIDFromSignPub(ed25519.PublicKey(sshPub.Marshal()))
		if got == wireID {
			t.Fatalf("iter %d: raw-key id unexpectedly equals wire-encoding id", i)
		}
	}
}

// TestCallerUserIDRejectsNonEd25519 verifies non-Ed25519 keys are rejected at
// the identity extraction boundary.
func TestCallerUserIDRejectsNonEd25519(t *testing.T) {
	// nil key.
	if _, err := callerUserID(nil); err == nil {
		t.Fatal("expected error for nil key")
	}

	// An RSA key: valid ssh.PublicKey but wrong type.
	rsaSigner := mustRSASigner(t)
	if _, err := callerUserID(rsaSigner.PublicKey()); err == nil {
		t.Fatal("expected error for RSA key")
	}
}

func TestPublicKeyHandler(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeyHandler(nil, ssh.PublicKey(sshPub)) {
		t.Fatal("ed25519 key should be accepted")
	}
	rsaSigner := mustRSASigner(t)
	if publicKeyHandler(nil, rsaSigner.PublicKey()) {
		t.Fatal("RSA key should be rejected")
	}
}

func TestDispatch(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		command []string
		wantRt  route
		wantID  string
	}{
		{"upload no command", "ignored", nil, routeUpload, ""},
		{"upload with flags", "ignored", []string{"-to", "addr"}, routeUpload, ""},
		{"list", "ignored", []string{"list"}, routeList, ""},
		{"list with flag", "ignored", []string{"list", "-received"}, routeList, ""},
		{"file download", "f:abcd", nil, routeFile, "abcd"},
		{"file rm", "f:abcd", []string{"rm"}, routeFile, "abcd"},
		{"empty file id", "f:", nil, routeFile, ""},
		// "list" as a file-request command must NOT be treated as list.
		{"file id named list-like", "f:list0000", []string{"list"}, routeFile, "list0000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, id := dispatch(tt.user, tt.command)
			if r != tt.wantRt || id != tt.wantID {
				t.Fatalf("dispatch(%q,%v) = (%d,%q), want (%d,%q)",
					tt.user, tt.command, r, id, tt.wantRt, tt.wantID)
			}
		})
	}
}

func TestFileIDValidator(t *testing.T) {
	// A real storage.NewID() output must pass the replicated validator; this
	// catches drift between storage's id parameters and ours.
	for i := 0; i < 100; i++ {
		id, err := storage.NewID()
		if err != nil {
			t.Fatal(err)
		}
		if !validFileID(id) {
			t.Fatalf("storage.NewID()=%q rejected by validFileID", id)
		}
	}

	bad := []string{
		"",                   // empty ("f:")
		"short",              // too short
		"0123456789abcdefg",  // 17 chars, too long
		"0123456789abcde$",   // illegal char
		"0123456789abcde ",   // space
		"0123456789abcd\x1b", // ANSI escape
	}
	for _, id := range bad {
		if validFileID(id) {
			t.Fatalf("validFileID(%q) = true, want false", id)
		}
	}
}

func TestParseFileCommand(t *testing.T) {
	if a, err := parseFileCommand(nil); err != nil || a != actionDownload {
		t.Fatalf("empty command: a=%v err=%v", a, err)
	}
	if a, err := parseFileCommand([]string{"rm"}); err != nil || a != actionDelete {
		t.Fatalf("rm: a=%v err=%v", a, err)
	}
	for _, cmd := range [][]string{{"ls"}, {"rm", "x"}, {"download"}, {"", ""}} {
		if _, err := parseFileCommand(cmd); err == nil {
			t.Fatalf("parseFileCommand(%v) expected invalid args", cmd)
		}
	}
}

func mustRSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("rsa signer: %v", err)
	}
	return ssh.Signer(signer)
}
