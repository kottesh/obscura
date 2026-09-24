package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kottesh/obscura/internal/carrier"
	"github.com/kottesh/obscura/internal/keystore"
	"github.com/kottesh/obscura/internal/pkgfmt"
	"github.com/kottesh/obscura/internal/sshclient"
	"golang.org/x/term"
)

// pngSignature is the 8-byte PNG file signature used to distinguish a PNG
// carrier from a raw pkgfmt package on download (spec 4 / 14). A raw package
// starts with the pkgfmt magic "OBSC".
var pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

// cmdReceive implements 'obscura receive <file_id> [-o <path>]' (spec 7, 14).
// It downloads the encrypted content, detects PNG vs raw package, extracts if
// needed, decrypts and verifies locally, then writes the plaintext. Plaintext
// is committed only after authentication, bounded decompression, and BLAKE3
// verification succeed. Without -o the bytes go to stdout only when stdout is
// not a TTY; on a TTY -o is required so binary bytes never hit a terminal.
func cmdReceive(ctx context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("receive")
	var out string
	fs.StringVar(&out, "o", "", "output path (default: stdout when not a TTY)")
	if err := parseCmd(fs, args, 1, 1); err != nil {
		return err
	}
	fileID := fs.Arg(0)

	if out == "" && stdoutIsTTY(env.stdout) {
		return usagef("receive: refusing to write binary output to a terminal; pass -o <path>")
	}
	if out == "" && env.g.mode == modeJSON() {
		// JSON receive reports metadata only and cannot carry binary plaintext
		// on stdout; require -o up front before any download/decrypt work.
		return usagef("receive: --json requires -o <path> for the decrypted bytes")
	}

	self, err := keystore.Load(env.g.configDir)
	if err != nil {
		return err
	}
	server, err := env.g.requireServer()
	if err != nil {
		return err
	}
	hostCB, err := env.g.hostKeyCallback()
	if err != nil {
		return err
	}

	client, err := sshclient.New(server, self.SignPriv, hostCB)
	if err != nil {
		return err
	}

	env.r.Stage("Downloading over SSH", fmt.Sprintf("id: %s", fileID))
	var dl bytes.Buffer
	if err := client.Download(ctx, fileID, &dl); err != nil {
		return err
	}

	pkg, err := extractPackage(env, self.BoxPriv, dl.Bytes())
	if err != nil {
		return err
	}

	// Pre-stage only: do not claim completion before pkgfmt.Open succeeds
	// (spec 8.2 — a completion stage is printed only after the operation
	// succeeds).
	env.r.Stage("Authenticating", "verifying package")
	plaintext, err := pkgfmt.Open(self.BoxPriv, pkg)
	if err != nil {
		// pkgfmt collapses parse/crypto/verify failures into one generic error;
		// surface a generic, non-revealing decrypt failure (spec 8.5).
		return fmt.Errorf("unable to decrypt: %w", err)
	}
	env.r.Crypto("Authenticated", "Poly1305 tag verified")
	env.r.Crypto("Verifying", "BLAKE3 matched")

	if env.g.mode == modeJSON() {
		// JSON receive reports metadata only; -o was validated up front.
		if err := writeAtomic(out, plaintext); err != nil {
			return err
		}
		return writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"command": "receive",
			"file_id": fileID,
			"path":    out,
			"size":    len(plaintext),
		})
	}

	if out == "" {
		// Non-TTY stdout: emit raw plaintext bytes with no decoration.
		if _, err := env.stdout.Write(plaintext); err != nil {
			return err
		}
		env.r.Success("File recovered", "written to stdout")
		return nil
	}

	if err := writeAtomic(out, plaintext); err != nil {
		return err
	}
	env.r.Success("File recovered", cleanPath(out))
	return nil
}

// extractPackage detects the carrier and returns the raw pkgfmt package bytes.
// For a PNG it runs carrier.Extract with a key-agreement closure that derives
// the stego shared secret from the receiver box private key and the ephemeral
// public key embedded in the PNG bootstrap. For a raw package it returns the
// bytes unchanged. Unknown leading bytes are a decode failure.
func extractPackage(env *cmdEnv, boxPriv *ecdh.PrivateKey, downloaded []byte) ([]byte, error) {
	switch {
	case bytes.HasPrefix(downloaded, pngSignature):
		env.r.Stage("Extracting PNG", "encrypted package found")
		pkg, err := carrier.Extract(carrierSharedSecret(boxPriv), downloaded)
		if err != nil {
			return nil, fmt.Errorf("extract png carrier: %w", err)
		}
		return pkg, nil
	case bytes.HasPrefix(downloaded, []byte(pkgfmt.Magic)):
		return downloaded, nil
	default:
		return nil, errors.New("unrecognized download: neither a PNG carrier nor an Obscura package")
	}
}

// carrierSharedSecret returns the key-agreement callback carrier.Extract uses to
// re-derive the stego shared secret: shared = ECDH(box_priv, ephemeral_pub),
// matching the sender's derivation in embedPNG.
func carrierSharedSecret(boxPriv *ecdh.PrivateKey) func([]byte) ([]byte, error) {
	return func(epk []byte) ([]byte, error) {
		ephPub, err := ecdh.X25519().NewPublicKey(epk)
		if err != nil {
			return nil, err
		}
		return boxPriv.ECDH(ephPub)
	}
}

// writeAtomic writes data to path via a temp file in the same directory followed
// by rename, so a reader never sees a partially written file and a failure
// leaves no committed output (spec 8.2/8.5: commit atomically, remove temporary
// output on failure). Plaintext is only ever passed here after authentication
// and verification succeed.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".obscura-recv-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("commit output: %w", err)
	}
	committed = true
	return nil
}

// stdoutIsTTY reports whether the command's stdout is a terminal. It is only a
// real terminal when stdout is an *os.File with a tty file descriptor; a
// bytes.Buffer (tests) or a pipe is never a TTY, so binary bytes flow there.
func stdoutIsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// cleanPath returns a tidy display form of an output path for the success card.
func cleanPath(p string) string {
	return filepath.Clean(p)
}
