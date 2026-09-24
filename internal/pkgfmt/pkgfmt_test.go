package pkgfmt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

// newReceiver returns a fresh X25519 keypair for use as a package receiver.
func newReceiver(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate receiver key: %v", err)
	}
	return priv
}

// makePayload returns a deterministic, moderately compressible payload of n bytes.
func makePayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		// Mix a repeating pattern (compressible) with position (some entropy).
		p[i] = byte(i%251) ^ byte(i>>8)
	}
	return p
}

func TestSealOpenRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"small", 100},
		{"one_kib", 1 << 10},
		{"few_kib", 4 * 1024},
		{"eight_kib", 8 * 1024},
		{"odd_size", 12345},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recv := newReceiver(t)
			payload := makePayload(tc.size)

			pkg, err := Seal(recv.PublicKey(), payload)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			// ciphertext_size invariant: 32 + compressed_size + 16.
			h, err := parseHeader(pkg, Limits{}.withDefaults())
			if err != nil {
				t.Fatalf("parseHeader: %v", err)
			}
			if got, want := h.ciphertextSize, expectedCiphertextSize(h.compressedSize); got != want {
				t.Fatalf("ciphertext_size = %d, want %d", got, want)
			}
			if got := uint64(len(pkg)); got != headerLen+h.ciphertextSize {
				t.Fatalf("package len = %d, want %d", got, headerLen+h.ciphertextSize)
			}
			if h.originalSize != uint64(tc.size) {
				t.Fatalf("original_size = %d, want %d", h.originalSize, tc.size)
			}

			out, err := Open(recv, pkg)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(out, payload) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(out), len(payload))
			}
		})
	}
}

func TestOpenWrongReceiver(t *testing.T) {
	recv := newReceiver(t)
	wrong := newReceiver(t)
	payload := makePayload(2048)

	pkg, err := Seal(recv.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := Open(wrong, pkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("wrong receiver: err = %v, want ErrInvalidPackage", err)
	}
	// Correct receiver still succeeds.
	if _, err := Open(recv, pkg); err != nil {
		t.Fatalf("correct receiver: %v", err)
	}
}

// TestOpenFlippedByte flips a single bit in every region of the package and
// asserts that Open rejects each mutation.
func TestOpenFlippedByte(t *testing.T) {
	recv := newReceiver(t)
	payload := makePayload(4096)
	pkg, err := Seal(recv.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Named header field byte offsets (spec 3.3 layout).
	offMagic := 0
	offVersion := magicLen
	offFlags := magicLen + versionLen
	offEph := offFlags + flagsLen
	offNonce := offEph + ephemeralPubLen
	offOrig := offNonce + nonceLen
	offComp := offOrig + sizeFieldLen
	offCipherSize := offComp + sizeFieldLen
	ciphertextStart := headerLen
	tagStart := len(pkg) - tagLen

	regions := []struct {
		name   string
		offset int
	}{
		{"magic", offMagic},
		{"version", offVersion},
		{"flags", offFlags},
		{"ephemeral_pub", offEph + 5},
		{"nonce", offNonce + 3},
		{"original_size", offOrig + 7},
		{"compressed_size", offComp + 7},
		{"ciphertext_size", offCipherSize + 7},
		{"ciphertext_body", ciphertextStart + 10},
		{"tag", tagStart + 4},
	}

	for _, r := range regions {
		t.Run(r.name, func(t *testing.T) {
			mutated := append([]byte(nil), pkg...)
			mutated[r.offset] ^= 0x01
			if _, err := Open(recv, mutated); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("flip %s@%d: err = %v, want ErrInvalidPackage", r.name, r.offset, err)
			}
		})
	}
}

func TestOpenTruncated(t *testing.T) {
	recv := newReceiver(t)
	pkg, err := Seal(recv.PublicKey(), makePayload(3000))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"partial_header", headerLen / 2},
		{"header_only", headerLen},
		{"header_plus_partial_ciphertext", headerLen + 5},
		{"missing_tag", len(pkg) - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trunc := pkg[:tc.n]
			if _, err := Open(recv, trunc); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("truncate to %d: err = %v, want ErrInvalidPackage", tc.n, err)
			}
		})
	}
}

func TestOpenTrailingGarbage(t *testing.T) {
	recv := newReceiver(t)
	pkg, err := Seal(recv.PublicKey(), makePayload(1500))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name    string
		trailer []byte
	}{
		{"one_byte", []byte{0x00}},
		{"many_bytes", bytes.Repeat([]byte{0xAB}, 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extended := append(append([]byte(nil), pkg...), tc.trailer...)
			if _, err := Open(recv, extended); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("trailing %s: err = %v, want ErrInvalidPackage", tc.name, err)
			}
		})
	}
}

func TestOpenBadMagicVersionFlags(t *testing.T) {
	recv := newReceiver(t)
	base, err := Seal(recv.PublicKey(), makePayload(512))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"bad_magic", func(p []byte) { p[0] = 'X' }},
		{"bad_version", func(p []byte) { p[magicLen] = 0x02 }},
		{"bad_flags_zero", func(p []byte) { p[magicLen+versionLen] = 0x00 }},
		{"bad_flags_extra_bit", func(p []byte) { p[magicLen+versionLen] = FlagZstandard | 0x02 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := append([]byte(nil), base...)
			tc.mutate(p)
			if _, err := Open(recv, p); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("%s: err = %v, want ErrInvalidPackage", tc.name, err)
			}
		})
	}
}

// buildBombPackage constructs a well-formed, correctly-authenticated package
// whose header claims a huge original_size but whose payload actually
// decompresses to a small size (or vice versa). It is used to exercise the
// bounded-decompression / size-mismatch defenses. Because it is signed with a
// valid content key, it passes AEAD authentication and reaches decompression.
func buildBombPackage(t *testing.T, recv *ecdh.PrivateKey, claimedOriginalSize uint64, realPayload []byte) []byte {
	t.Helper()

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("eph key: %v", err)
	}
	contentKey, err := deriveContentKey(ephPriv, recv.PublicKey())
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	compressed := enc.EncodeAll(realPayload, nil)
	_ = enc.Close()

	hash := blake3.Sum256(realPayload)
	plaintext := append(append([]byte(nil), hash[:]...), compressed...)

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}

	h := header{
		flags:          FlagZstandard,
		ephemeralPub:   ephPriv.PublicKey().Bytes(),
		nonce:          nonce,
		originalSize:   claimedOriginalSize,
		compressedSize: uint64(len(compressed)),
		ciphertextSize: expectedCiphertextSize(uint64(len(compressed))),
	}
	aad := h.aad()

	aead, err := chacha20poly1305.NewX(contentKey)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	out := append([]byte(nil), aad...)
	out = aead.Seal(out, nonce, plaintext, aad)
	return out
}

func TestOpenDecompressionBomb(t *testing.T) {
	recv := newReceiver(t)

	// A small compressed payload (highly compressible zeros) whose header
	// claims a massive original_size well beyond the default cap.
	real := make([]byte, 4096) // decompresses to 4096 zeros
	huge := uint64(DefaultMaxOriginalSize) + 1
	pkg := buildBombPackage(t, recv, huge, real)

	if _, err := Open(recv, pkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("bomb (oversized original_size): err = %v, want ErrInvalidPackage", err)
	}
}

// TestDecompressBoundedCapLimit exercises the decompression-bomb defense at
// the exact seam the reviewer flagged: WithDecodeAllCapLimit(true) on the
// shared decoder plus cap(dst)=originalSize in decompressBounded. Every
// Open-level bomb test above is stopped earlier (header original_size >
// MaxOriginalSize, or the post-decode size-mismatch check), so none of them
// actually depend on the cap.
//
// Here originalSize is a small, fully valid value (1024: under MaxOriginalSize
// and well within limits) while the zstd frame decompresses to far more
// (64 KiB of zeros). With the cap in place, DecodeAll refuses to write past
// cap(dst)-len(dst)=1024 and returns an error, which decompressBounded maps to
// errDecompress. The test asserts errDecompress specifically.
//
// This makes the test load-bearing: if WithDecodeAllCapLimit(true) or the
// cap(dst)=originalSize sizing is removed, DecodeAll instead succeeds and
// returns all 65536 bytes, so decompressBounded reaches its length check and
// returns errSizeMismatch (not errDecompress) — failing this assertion.
func TestDecompressBoundedCapLimit(t *testing.T) {
	const claimedOriginalSize = 1024

	// A frame that decompresses to far more than claimedOriginalSize.
	real := make([]byte, 64*1024) // 64 KiB of zeros, highly compressible
	frame := compress(real)

	// Sanity: claimedOriginalSize must pass the in-bounds guard so the branch
	// under test (the cap) is what rejects it, not the MaxOriginalSize check.
	if claimedOriginalSize > DefaultMaxOriginalSize {
		t.Fatalf("claimedOriginalSize %d must be <= DefaultMaxOriginalSize", claimedOriginalSize)
	}

	_, err := decompressBounded(frame, claimedOriginalSize)
	if !errors.Is(err, errDecompress) {
		t.Fatalf("decompressBounded past cap: err = %v, want errDecompress "+
			"(cap limit removed would yield errSizeMismatch)", err)
	}
}

func TestOpenSizeMismatch(t *testing.T) {
	recv := newReceiver(t)

	real := makePayload(4096)
	// Claim a wrong-but-in-bounds original_size: decompression will produce
	// 4096 bytes but the header claims 5000.
	pkg := buildBombPackage(t, recv, 5000, real)

	if _, err := Open(recv, pkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("size mismatch: err = %v, want ErrInvalidPackage", err)
	}
}

func TestOpenBoundedByCustomLimit(t *testing.T) {
	recv := newReceiver(t)
	payload := makePayload(16 * 1024)
	pkg, err := Seal(recv.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// A MaxOriginalSize below the real payload size must reject the package.
	small := Limits{MaxOriginalSize: 1024}
	if _, err := OpenWithLimits(recv, pkg, small); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("custom original limit: err = %v, want ErrInvalidPackage", err)
	}

	// A MaxPackageSize below the encoded size must reject the package.
	smallPkg := Limits{MaxPackageSize: uint64(len(pkg) - 1)}
	if _, err := OpenWithLimits(recv, pkg, smallPkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("custom package limit: err = %v, want ErrInvalidPackage", err)
	}
}

func TestCiphertextSizeInvariant(t *testing.T) {
	recv := newReceiver(t)
	for _, size := range []int{0, 1, 500, 4096} {
		pkg, err := Seal(recv.PublicKey(), makePayload(size))
		if err != nil {
			t.Fatalf("Seal(%d): %v", size, err)
		}
		ctSize := binary.BigEndian.Uint64(pkg[headerLen-sizeFieldLen : headerLen])
		compSize := binary.BigEndian.Uint64(pkg[headerLen-2*sizeFieldLen : headerLen-sizeFieldLen])
		if ctSize != hashLen+compSize+tagLen {
			t.Fatalf("size=%d: ciphertext_size=%d, want %d", size, ctSize, hashLen+compSize+tagLen)
		}
		if uint64(len(pkg)) != headerLen+ctSize {
			t.Fatalf("size=%d: len(pkg)=%d, want %d", size, len(pkg), headerLen+ctSize)
		}
	}
}

func TestSealNilKey(t *testing.T) {
	if _, err := Seal(nil, makePayload(10)); err == nil {
		t.Fatal("Seal(nil): expected error")
	}
}

func TestOpenNilKey(t *testing.T) {
	recv := newReceiver(t)
	pkg, err := Seal(recv.PublicKey(), makePayload(10))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(nil, pkg); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("Open(nil): err = %v, want ErrInvalidPackage", err)
	}
}
