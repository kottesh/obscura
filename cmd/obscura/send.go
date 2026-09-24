package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/kottesh/obscura/internal/carrier"
	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/keystore"
	"github.com/kottesh/obscura/internal/pkgfmt"
	"github.com/kottesh/obscura/internal/sshclient"
	"github.com/kottesh/obscura/internal/storage"
)

// cmdSend implements 'obscura send <path> --to <address> [--name <name>]
// [--png]' (spec 7, 8.2). It reads the file, seals it to the receiver's box
// public key, optionally embeds the package in a generated PNG carrier, uploads
// over SSH, and prints the returned file id to stdout. Progress cards go to
// stderr only.
func cmdSend(ctx context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("send")
	var (
		to   string
		name string
		png  bool
	)
	fs.StringVar(&to, "to", "", "receiver address (required)")
	fs.StringVar(&name, "name", "", "optional display name")
	fs.BoolVar(&png, "png", false, "embed the encrypted package in a generated PNG")
	if err := parseCmd(fs, args, 1, 1); err != nil {
		return err
	}
	path := fs.Arg(0)
	if to == "" {
		return usagef("send: --to <address> is required")
	}

	addr, err := identity.DecodeAddress(to)
	if err != nil {
		return usagef("send: invalid --to address: %v", err)
	}

	// The sender needs its own identity only to authenticate the SSH upload;
	// encryption uses the receiver's box public key from the address.
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

	// Reading stage: load the file as opaque bytes (spec 3.1).
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	env.r.Stage("Reading file", fmt.Sprintf("%s · %s", displayName(path, name), humanBytes(len(payload))))

	// Encrypting stage: pkgfmt.Seal compresses, hashes, and AEAD-seals to the
	// receiver box public key (spec 3.2). Compression happens inside Seal, so we
	// surface the encrypting card once.
	env.r.Crypto("Encrypting", "X25519 · XChaCha20-Poly1305")
	pkg, err := pkgfmt.Seal(addr.BoxPub, payload)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	body := pkg
	carrierType := string(storage.PackageCarrier)
	if png {
		stego, embErr := embedPNG(addr.BoxPub, pkg)
		if embErr != nil {
			return fmt.Errorf("embed png: %w", embErr)
		}
		body = stego
		carrierType = string(storage.PNGCarrier)
		env.r.Stage("Embedding PNG", fmt.Sprintf("generated cover · %s", humanBytes(len(stego))))
	}

	env.r.Stage("Uploading over SSH", fmt.Sprintf("receiver: %s", shortHex(addr.UserID[:])))

	client, err := sshclient.New(server, self.SignPriv, hostCB)
	if err != nil {
		return err
	}
	fileID, err := client.Upload(ctx, bytes.NewReader(body), to, name, carrierType)
	if err != nil {
		return err
	}

	if env.g.mode == modeJSON() {
		return writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"command": "send",
			"file_id": fileID,
			"carrier": carrierType,
			"size":    len(body),
		})
	}

	env.r.Success("File shared", fmt.Sprintf("id: %s", fileID))
	fmt.Fprintln(env.stdout, fileID)
	return nil
}

// embedPNG hides an already-sealed package inside a freshly generated PNG. The
// carrier's stego positions are keyed by a shared secret derived from a fresh
// ephemeral X25519 keypair and the receiver's box public key; the ephemeral
// public key is stored in the PNG bootstrap so the receiver can re-derive the
// same shared secret with its box private key. This carrier ephemeral key is
// independent of the ephemeral key inside the pkgfmt package: the carrier
// treats the package as opaque bytes (spec 4).
func embedPNG(receiverBoxPub *ecdh.PublicKey, pkg []byte) ([]byte, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate carrier ephemeral key: %w", err)
	}
	shared, err := ephPriv.ECDH(receiverBoxPub)
	if err != nil {
		return nil, fmt.Errorf("carrier key agreement: %w", err)
	}
	return carrier.Embed(shared, ephPriv.PublicKey().Bytes(), pkg)
}

// displayName picks the label to show in the Reading card: the explicit --name
// when given, otherwise the base name of the source path.
func displayName(path, name string) string {
	if name != "" {
		return name
	}
	return baseName(path)
}
