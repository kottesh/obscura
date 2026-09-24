package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/kottesh/obscura/internal/pkgfmt"
)

// Header layout constants for read-only inspection of a pkgfmt package. These
// mirror the on-wire header in internal/pkgfmt (spec 3.3) and are used only to
// display non-secret metadata; inspect never decrypts and never prints keys or
// plaintext (spec 7).
const (
	inspHeaderLen       = 86 // magic(4)+ver(1)+flags(1)+epk(32)+nonce(24)+3*size(8)
	inspOffOriginalSize = 62
	inspOffCompressed   = 70
	inspOffCiphertext   = 78
)

// cmdInspect implements 'obscura inspect <package_or_png>' (spec 7). It reads a
// local file, sniffs whether it is a PNG carrier or a raw package, and prints
// non-secret metadata (format version, carrier type, sizes) to stdout. It never
// prints keys or plaintext and never contacts the server.
func cmdInspect(_ context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("inspect")
	if err := parseCmd(fs, args, 1, 1); err != nil {
		return err
	}
	path := fs.Arg(0)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	meta, err := inspectBytes(data)
	if err != nil {
		return err
	}

	if env.g.mode == modeJSON() {
		obj := map[string]any{
			"version": jsonVersion,
			"command": "inspect",
			"carrier": meta.carrier,
			"size":    meta.totalSize,
		}
		if meta.hasPackage {
			obj["format_version"] = meta.formatVersion
			obj["original_size"] = meta.originalSize
			obj["compressed_size"] = meta.compressedSize
			obj["ciphertext_size"] = meta.ciphertextSize
		}
		return writeJSON(env.stdout, obj)
	}

	fmt.Fprintf(env.stdout, "carrier: %s\n", meta.carrier)
	fmt.Fprintf(env.stdout, "size: %d\n", meta.totalSize)
	if meta.hasPackage {
		fmt.Fprintf(env.stdout, "format_version: %d\n", meta.formatVersion)
		fmt.Fprintf(env.stdout, "original_size: %d\n", meta.originalSize)
		fmt.Fprintf(env.stdout, "compressed_size: %d\n", meta.compressedSize)
		fmt.Fprintf(env.stdout, "ciphertext_size: %d\n", meta.ciphertextSize)
	}
	env.r.Stage("Inspected", fmt.Sprintf("%s · %s", meta.carrier, humanBytes(meta.totalSize)))
	return nil
}

// inspectMeta holds the non-secret metadata surfaced by inspect.
type inspectMeta struct {
	carrier        string // "package" or "png"
	totalSize      int
	hasPackage     bool // whether raw package header fields are available
	formatVersion  byte
	originalSize   uint64
	compressedSize uint64
	ciphertextSize uint64
}

// inspectBytes classifies data and, when it is a raw package, decodes only the
// non-secret header fields. For a PNG carrier the package is embedded and keyed
// by a shared secret we do not have here, so only the carrier type and total
// size are reported (no decryption is attempted).
func inspectBytes(data []byte) (inspectMeta, error) {
	switch {
	case bytes.HasPrefix(data, pngSignature):
		return inspectMeta{carrier: "png", totalSize: len(data)}, nil
	case bytes.HasPrefix(data, []byte(pkgfmt.Magic)):
		return inspectPackageHeader(data)
	default:
		return inspectMeta{}, errors.New("unrecognized file: neither a PNG carrier nor an Obscura package")
	}
}

// inspectPackageHeader validates the fixed header framing and extracts the
// non-secret size fields. It does not derive keys, decrypt, or authenticate;
// full validation is the receive path's job.
func inspectPackageHeader(data []byte) (inspectMeta, error) {
	if len(data) < inspHeaderLen {
		return inspectMeta{}, errors.New("truncated package header")
	}
	if data[4] != pkgfmt.Version {
		return inspectMeta{}, fmt.Errorf("unsupported package version 0x%02x", data[4])
	}
	return inspectMeta{
		carrier:        "package",
		totalSize:      len(data),
		hasPackage:     true,
		formatVersion:  data[4],
		originalSize:   binary.BigEndian.Uint64(data[inspOffOriginalSize : inspOffOriginalSize+8]),
		compressedSize: binary.BigEndian.Uint64(data[inspOffCompressed : inspOffCompressed+8]),
		ciphertextSize: binary.BigEndian.Uint64(data[inspOffCiphertext : inspOffCiphertext+8]),
	}, nil
}
