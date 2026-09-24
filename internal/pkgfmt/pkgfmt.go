// Package pkgfmt implements the Obscura encrypted file package described in the
// system specification (sections 3, 11 and 14).
//
// A package binds an ephemeral X25519 key, a random XChaCha20-Poly1305 nonce,
// the plaintext/compressed sizes, and the ciphertext (which embeds the
// Poly1305 tag) into a single, self-describing, authenticated frame. Every
// fixed header field is fed to the AEAD as additional authenticated data, so
// tampering with any header byte breaks authentication.
//
// The receiver pipeline is strictly authenticate-then-process: the AEAD tag is
// verified before any decompression, decompression is bounded to exactly the
// claimed original size (defending against decompression bombs), and the
// embedded BLAKE3 hash is checked before a single plaintext byte is returned.
package pkgfmt

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

// Wire-format constants for the EncryptedFile header (spec 3.3).
const (
	// Magic is the 4-byte package identifier.
	Magic = "OBSC"

	// Version is the current package format version.
	Version byte = 0x01

	// magicLen, versionLen and flagsLen are the sizes of the leading scalar
	// header fields.
	magicLen   = 4
	versionLen = 1
	flagsLen   = 1

	// ephemeralPubLen is the size of the ephemeral X25519 public key.
	ephemeralPubLen = 32
	// nonceLen is the XChaCha20-Poly1305 (extended) nonce size.
	nonceLen = chacha20poly1305.NonceSizeX // 24
	// sizeFieldLen is the width of each big-endian size field.
	sizeFieldLen = 8

	// hashLen is the size of the embedded BLAKE3 hash prepended to the
	// compressed payload before encryption.
	hashLen = 32
	// tagLen is the Poly1305 authentication tag length.
	tagLen = chacha20poly1305.Overhead // 16
	// keyLen is the derived content-key length.
	keyLen = chacha20poly1305.KeySize // 32
)

// FlagZstandard marks that the payload was compressed with Zstandard (spec 3.3
// flags bit 0). Version 1 always sets this flag.
const FlagZstandard byte = 0x01

// headerLen is the total size of the fixed header (everything before the
// ciphertext). This is also the exact length of the AAD.
const headerLen = magicLen + versionLen + flagsLen + ephemeralPubLen + nonceLen + sizeFieldLen*3

// contentKeyInfo is the HKDF-SHA256 info label for the file content key. It is
// part of the wire contract and must not change without a version bump.
const contentKeyInfo = "obscura/file-content/v1"

// Exported size limits (spec 11). These are the defaults enforced by Seal and
// Open. Callers that need different bounds can use OpenWithLimits.
const (
	// DefaultMaxPackageSize bounds the total encoded package size (header plus
	// ciphertext). This caps how much a receiver will parse and allocate.
	DefaultMaxPackageSize = 1 << 30 // 1 GiB

	// DefaultMaxOriginalSize bounds the decompressed payload size. It is the
	// hard cap on the destination buffer used for bounded decompression.
	DefaultMaxOriginalSize = 1 << 30 // 1 GiB
)

// Sentinel errors used internally and in tests. Open never leaks which of
// these occurred to its caller; it always returns ErrInvalidPackage so that a
// tampering party cannot distinguish parse failures from crypto failures.
var (
	// ErrInvalidPackage is the single generic error returned by Open for any
	// parse, size, authentication, decompression, or verification failure.
	ErrInvalidPackage = errors.New("pkgfmt: invalid package")

	errBadMagic       = errors.New("pkgfmt: bad magic")
	errBadVersion     = errors.New("pkgfmt: unsupported version")
	errBadFlags       = errors.New("pkgfmt: unsupported flags")
	errShortHeader    = errors.New("pkgfmt: truncated header")
	errSizeOverflow   = errors.New("pkgfmt: size field exceeds limit")
	errSizeInvariant  = errors.New("pkgfmt: ciphertext_size invariant violated")
	errTrailingBytes  = errors.New("pkgfmt: trailing bytes after ciphertext")
	errShortCipher    = errors.New("pkgfmt: truncated ciphertext")
	errAuth           = errors.New("pkgfmt: authentication failed")
	errDecompress     = errors.New("pkgfmt: decompression failed")
	errSizeMismatch   = errors.New("pkgfmt: decompressed size mismatch")
	errHashMismatch   = errors.New("pkgfmt: content hash mismatch")
	errPackageTooBig  = errors.New("pkgfmt: package exceeds maximum size")
	errOriginalTooBig = errors.New("pkgfmt: original size exceeds maximum")
)

// Limits configures the bounds enforced when opening a package.
type Limits struct {
	// MaxPackageSize bounds the total encoded package length. Zero means use
	// DefaultMaxPackageSize.
	MaxPackageSize uint64
	// MaxOriginalSize bounds the decompressed payload length. Zero means use
	// DefaultMaxOriginalSize.
	MaxOriginalSize uint64
}

func (l Limits) withDefaults() Limits {
	if l.MaxPackageSize == 0 {
		l.MaxPackageSize = DefaultMaxPackageSize
	}
	if l.MaxOriginalSize == 0 {
		l.MaxOriginalSize = DefaultMaxOriginalSize
	}
	return l
}

// header holds the parsed fixed fields of an EncryptedFile.
type header struct {
	flags          byte
	ephemeralPub   []byte // ephemeralPubLen bytes
	nonce          []byte // nonceLen bytes
	originalSize   uint64
	compressedSize uint64
	ciphertextSize uint64
}

// aad returns the canonical additional-authenticated-data encoding of the
// fixed header. The layout is exactly the on-wire header bytes, in order:
//
//	offset  size  field
//	0       4     magic            "OBSC"
//	4       1     version          0x01
//	5       1     flags
//	6       32    ephemeral_pub
//	38      24    nonce
//	62      8     original_size    (big-endian uint64)
//	70      8     compressed_size  (big-endian uint64)
//	78      8     ciphertext_size  (big-endian uint64)
//	86            (end; total headerLen = 86 bytes)
//
// The AAD is the first headerLen bytes of the encoded package, i.e. everything
// preceding the ciphertext. Any modification to a header field changes the AAD
// and causes AEAD authentication to fail.
func (h header) aad() []byte {
	buf := make([]byte, 0, headerLen)
	buf = append(buf, Magic...)
	buf = append(buf, Version)
	buf = append(buf, h.flags)
	buf = append(buf, h.ephemeralPub...)
	buf = append(buf, h.nonce...)
	buf = binary.BigEndian.AppendUint64(buf, h.originalSize)
	buf = binary.BigEndian.AppendUint64(buf, h.compressedSize)
	buf = binary.BigEndian.AppendUint64(buf, h.ciphertextSize)
	return buf
}

// expectedCiphertextSize returns the version-1 ciphertext_size invariant:
// hash (32) + compressed_size + tag (16).
func expectedCiphertextSize(compressedSize uint64) uint64 {
	return hashLen + compressedSize + tagLen
}

// deriveContentKey computes the shared secret and derives the content key.
// crypto/ecdh rejects all-zero / low-order-point results, and that error is
// surfaced to the caller.
func deriveContentKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, contentKeyInfo, keyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Seal encrypts payload to receiverBoxPub and returns a complete EncryptedFile
// package (spec 3.2). It generates a fresh ephemeral X25519 keypair and a
// random 24-byte nonce for every call.
func Seal(receiverBoxPub *ecdh.PublicKey, payload []byte) ([]byte, error) {
	if receiverBoxPub == nil {
		return nil, errors.New("pkgfmt: nil receiver key")
	}
	if uint64(len(payload)) > DefaultMaxOriginalSize {
		return nil, errOriginalTooBig
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pkgfmt: generate ephemeral key: %w", err)
	}

	contentKey, err := deriveContentKey(ephPriv, receiverBoxPub)
	if err != nil {
		return nil, fmt.Errorf("pkgfmt: derive content key: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("pkgfmt: generate nonce: %w", err)
	}

	compressed := compress(payload)
	hash := blake3.Sum256(payload)

	// plaintext = hash || compressed
	plaintext := make([]byte, 0, hashLen+len(compressed))
	plaintext = append(plaintext, hash[:]...)
	plaintext = append(plaintext, compressed...)

	h := header{
		flags:          FlagZstandard,
		ephemeralPub:   ephPriv.PublicKey().Bytes(),
		nonce:          nonce,
		originalSize:   uint64(len(payload)),
		compressedSize: uint64(len(compressed)),
		ciphertextSize: expectedCiphertextSize(uint64(len(compressed))),
	}

	aead, err := chacha20poly1305.NewX(contentKey)
	if err != nil {
		return nil, fmt.Errorf("pkgfmt: init aead: %w", err)
	}

	aad := h.aad()
	// Append the ciphertext directly after the header bytes; aad already holds
	// the full header, so reuse it as the seal destination prefix.
	out := make([]byte, headerLen, headerLen+len(plaintext)+tagLen)
	copy(out, aad)
	out = aead.Seal(out, nonce, plaintext, aad)

	if uint64(len(out)) > DefaultMaxPackageSize {
		return nil, errPackageTooBig
	}
	return out, nil
}

// Open decrypts and verifies pkg using receiverBoxPriv and returns the original
// payload (spec 14). It enforces the default limits. On any failure it returns
// ErrInvalidPackage without revealing which step failed.
func Open(receiverBoxPriv *ecdh.PrivateKey, pkg []byte) ([]byte, error) {
	return OpenWithLimits(receiverBoxPriv, pkg, Limits{})
}

// OpenWithLimits behaves like Open but uses the supplied limits (with defaults
// filled in for zero fields).
func OpenWithLimits(receiverBoxPriv *ecdh.PrivateKey, pkg []byte, limits Limits) ([]byte, error) {
	payload, err := open(receiverBoxPriv, pkg, limits.withDefaults())
	if err != nil {
		// Collapse every internal failure to the generic sentinel so callers
		// (and attackers) cannot distinguish parse from crypto failures.
		return nil, ErrInvalidPackage
	}
	return payload, nil
}

func open(priv *ecdh.PrivateKey, pkg []byte, limits Limits) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("pkgfmt: nil receiver key")
	}
	if uint64(len(pkg)) > limits.MaxPackageSize {
		return nil, errPackageTooBig
	}

	h, err := parseHeader(pkg, limits)
	if err != nil {
		return nil, err
	}

	// Exact ciphertext bounds: header followed by ciphertextSize bytes and
	// nothing else. Reject trailing frames/garbage.
	end := headerLen + h.ciphertextSize
	if uint64(len(pkg)) < end {
		return nil, errShortCipher
	}
	if uint64(len(pkg)) > end {
		return nil, errTrailingBytes
	}
	ciphertext := pkg[headerLen:end]

	ephPub, err := ecdh.X25519().NewPublicKey(h.ephemeralPub)
	if err != nil {
		return nil, err
	}
	contentKey, err := deriveContentKey(priv, ephPub)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(contentKey)
	if err != nil {
		return nil, err
	}

	// AAD is the exact leading headerLen bytes of the package.
	aad := pkg[:headerLen]
	plaintext, err := aead.Open(nil, h.nonce, ciphertext, aad)
	if err != nil {
		return nil, errAuth
	}

	// plaintext = hash (32) || compressed
	if len(plaintext) < hashLen {
		return nil, errAuth
	}
	expectedHash := plaintext[:hashLen]
	compressed := plaintext[hashLen:]
	if uint64(len(compressed)) != h.compressedSize {
		return nil, errSizeMismatch
	}

	payload, err := decompressBounded(compressed, h.originalSize)
	if err != nil {
		return nil, err
	}

	got := blake3.Sum256(payload)
	if subtleEqual(got[:], expectedHash) == false {
		return nil, errHashMismatch
	}
	return payload, nil
}

// parseHeader validates and decodes the fixed header. All size fields are
// checked against the configured limits before any allocation.
func parseHeader(pkg []byte, limits Limits) (header, error) {
	if len(pkg) < headerLen {
		return header{}, errShortHeader
	}

	off := 0
	if string(pkg[off:off+magicLen]) != Magic {
		return header{}, errBadMagic
	}
	off += magicLen

	if pkg[off] != Version {
		return header{}, errBadVersion
	}
	off += versionLen

	flags := pkg[off]
	off += flagsLen
	// Version 1 requires the Zstandard flag and defines no other bits.
	if flags != FlagZstandard {
		return header{}, errBadFlags
	}

	ephemeralPub := pkg[off : off+ephemeralPubLen]
	off += ephemeralPubLen

	nonce := pkg[off : off+nonceLen]
	off += nonceLen

	originalSize := binary.BigEndian.Uint64(pkg[off : off+sizeFieldLen])
	off += sizeFieldLen
	compressedSize := binary.BigEndian.Uint64(pkg[off : off+sizeFieldLen])
	off += sizeFieldLen
	ciphertextSize := binary.BigEndian.Uint64(pkg[off : off+sizeFieldLen])

	if originalSize > limits.MaxOriginalSize {
		return header{}, errOriginalTooBig
	}
	if ciphertextSize > limits.MaxPackageSize {
		return header{}, errSizeOverflow
	}
	// Reject an out-of-range compressed size before the invariant check so a
	// near-2^64 value cannot wrap addition and satisfy the invariant against a
	// small ciphertext_size. compressed_size can never exceed the package cap.
	if compressedSize > limits.MaxPackageSize {
		return header{}, errSizeOverflow
	}
	// Enforce the version-1 ciphertext_size invariant before trusting the
	// declared compressed size or reading the ciphertext.
	if ciphertextSize != expectedCiphertextSize(compressedSize) {
		return header{}, errSizeInvariant
	}

	return header{
		flags:          flags,
		ephemeralPub:   ephemeralPub,
		nonce:          nonce,
		originalSize:   originalSize,
		compressedSize: compressedSize,
		ciphertextSize: ciphertextSize,
	}, nil
}
