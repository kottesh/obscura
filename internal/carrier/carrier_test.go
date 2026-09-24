package carrier

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"image"
	"image/png"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// fixedShared returns a deterministic 32-byte shared secret for tests.
func fixedShared() []byte {
	s := make([]byte, seedSize)
	for i := range s {
		s[i] = byte(0xA0 + i)
	}
	return s
}

// fixedEpk returns a deterministic 32-byte ephemeral public key for tests.
func fixedEpk() []byte {
	e := make([]byte, epkSize)
	for i := range e {
		e[i] = byte(i * 7)
	}
	return e
}

// staticCallback returns a callback that ignores E_pk and returns the fixed
// shared secret, standing in for a real X25519 key agreement in unit tests.
func staticCallback(shared []byte) func([]byte) ([]byte, error) {
	return func(_ []byte) ([]byte, error) {
		out := make([]byte, len(shared))
		copy(out, shared)
		return out, nil
	}
}

func TestEmbedExtractRoundTrip(t *testing.T) {
	shared := fixedShared()
	epk := fixedEpk()

	tests := []struct {
		name string
		body []byte
	}{
		{"empty", []byte{}},
		{"tiny", []byte("x")},
		{"eleven", []byte("hello world")},
		{"binary", func() []byte {
			b := make([]byte, 512)
			for i := range b {
				b[i] = byte(i * 31)
			}
			return b
		}()},
		{"medium", bytes.Repeat([]byte("obscura-"), 400)},
		{"large", func() []byte {
			b := make([]byte, 8192)
			for i := range b {
				b[i] = byte(i*13 + 7)
			}
			return b
		}()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pngBytes, err := Embed(shared, epk, tc.body)
			if err != nil {
				t.Fatalf("Embed: %v", err)
			}
			got, err := Extract(staticCallback(shared), pngBytes)
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Fatalf("round trip mismatch: got %d bytes, want %d bytes", len(got), len(tc.body))
			}
		})
	}
}

func TestExtractRecoversEpkForCallback(t *testing.T) {
	shared := fixedShared()
	epk := fixedEpk()

	pngBytes, err := Embed(shared, epk, []byte("payload"))
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	var seen []byte
	cb := func(gotEpk []byte) ([]byte, error) {
		seen = append([]byte(nil), gotEpk...)
		return shared, nil
	}
	if _, err := Extract(cb, pngBytes); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !bytes.Equal(seen, epk) {
		t.Fatalf("callback received epk %x, want %x", seen, epk)
	}
}

func TestAlphaUnchanged(t *testing.T) {
	shared := fixedShared()
	epk := fixedEpk()
	body := bytes.Repeat([]byte{0x5A}, 1024)

	pngBytes, err := Embed(shared, epk, body)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	img, err := decodeNRGBA(pngBytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			off := y*img.Stride + x*4 + 3
			if img.Pix[off] != 0xff {
				t.Fatalf("alpha changed at (%d,%d): %d", x, y, img.Pix[off])
			}
		}
	}
}

func TestCapacityOverflowRejected(t *testing.T) {
	tests := []struct {
		name         string
		payloadSlots int
		wantErr      bool
	}{
		{"zero", 0, false},
		{"small", 800, false},
		{"negative", -1, true},
		{"overflow_mul", maxInt/bodySlotFraction + 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := planImage(tc.payloadSlots)
			if tc.wantErr && err == nil {
				t.Fatalf("planImage(%d): expected error, got nil", tc.payloadSlots)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("planImage(%d): unexpected error %v", tc.payloadSlots, err)
			}
		})
	}
}

func TestExtractRejectsOversizedBodyLength(t *testing.T) {
	shared := fixedShared()
	epk := fixedEpk()

	pngBytes, err := Embed(shared, epk, []byte("real body"))
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	// Rewrite the embedded header body_length to an oversized value directly in
	// the shuffled payload region so Extract's bound check must reject it.
	img, err := decodeNRGBA(pngBytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	positions, err := derivePositions(shared, img.Rect.Dx(), img.Rect.Dy())
	if err != nil {
		t.Fatalf("derivePositions: %v", err)
	}
	// header layout: [0]=S [1]=F [2]=version [3..11)=len. Write huge length.
	var lenBytes [headerLenBytes]byte
	binary.BigEndian.PutUint64(lenBytes[:], maxBodyLen+1)
	// Write the length field bits (byte indices 3..10) via matchSlot with a
	// throwaway matching stream; parity is all that matters for readback.
	m, err := newStream(shared, matchingInfo)
	if err != nil {
		t.Fatalf("newStream: %v", err)
	}
	for byteIdx := 0; byteIdx < headerLenBytes; byteIdx++ {
		by := lenBytes[byteIdx]
		for j := 0; j < 8; j++ {
			bit := (by >> (7 - uint(j))) & 1
			slot := positions[(3+byteIdx)*8+j]
			matchSlot(img, slot, bit, m)
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if _, err := Extract(staticCallback(shared), buf.Bytes()); !errors.Is(err, errMalformed) {
		t.Fatalf("expected errMalformed for oversized body_length, got %v", err)
	}
}

func TestDeterministicPositionsExcludeBootstrap(t *testing.T) {
	shared := fixedShared()
	const w, h = 64, 64

	p1, err := derivePositions(shared, w, h)
	if err != nil {
		t.Fatalf("derivePositions #1: %v", err)
	}
	p2, err := derivePositions(shared, w, h)
	if err != nil {
		t.Fatalf("derivePositions #2: %v", err)
	}

	// Determinism: identical secret and dimensions yield identical order.
	if len(p1) != len(p2) {
		t.Fatalf("length mismatch %d vs %d", len(p1), len(p2))
	}
	for i := range p1 {
		if p1[i] != p2[i] {
			t.Fatalf("nondeterministic position at %d: %d vs %d", i, p1[i], p2[i])
		}
	}

	total := w * h * 3
	eligible := total - bootstrapSlots
	if len(p1) != eligible {
		t.Fatalf("eligible count = %d, want %d", len(p1), eligible)
	}

	// Every position is a valid permutation of [bootstrapSlots, total) and no
	// bootstrap slot [0,256) appears.
	seen := make(map[int]bool, len(p1))
	for _, s := range p1 {
		if s < bootstrapSlots {
			t.Fatalf("bootstrap slot %d leaked into positions", s)
		}
		if s >= total {
			t.Fatalf("out-of-range slot %d (total %d)", s, total)
		}
		if seen[s] {
			t.Fatalf("duplicate slot %d", s)
		}
		seen[s] = true
	}
	if len(seen) != eligible {
		t.Fatalf("permutation covered %d slots, want %d", len(seen), eligible)
	}

	// A different secret must produce a different order (overwhelmingly likely).
	other := fixedShared()
	other[0] ^= 0xff
	p3, err := derivePositions(other, w, h)
	if err != nil {
		t.Fatalf("derivePositions other: %v", err)
	}
	same := true
	for i := range p1 {
		if p1[i] != p3[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("different secrets produced identical position order")
	}
}

func TestPixelMutationBreaksExtraction(t *testing.T) {
	shared := fixedShared()
	epk := fixedEpk()
	body := bytes.Repeat([]byte("A"), 2048)

	pngBytes, err := Embed(shared, epk, body)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	img, err := decodeNRGBA(pngBytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Flip the LSB of many RGB channels across the image so a header or body
	// slot is corrupted regardless of the shuffle, forcing failure or a wrong
	// body. We flip every 5th channel byte, skipping alpha.
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			for ch := 0; ch < 3; ch++ {
				off := y*img.Stride + x*4 + ch
				if off%5 == 0 {
					img.Pix[off] ^= 1
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("re-encode: %v", err)
	}

	got, err := Extract(staticCallback(shared), buf.Bytes())
	if err == nil && bytes.Equal(got, body) {
		t.Fatalf("mutation did not affect extraction: body extracted intact")
	}
}

func TestPNGReDecodeLossless(t *testing.T) {
	shared := fixedShared()
	epk := fixedEpk()
	body := bytes.Repeat([]byte{0xC3, 0x3C}, 700)

	pngBytes, err := Embed(shared, epk, body)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	// Decode, re-encode, decode again: NRGBA pixels must be byte-identical, so
	// the carrier survives a lossless PNG round trip.
	img1, err := decodeNRGBA(pngBytes)
	if err != nil {
		t.Fatalf("decode #1: %v", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img1); err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	img2, err := decodeNRGBA(buf.Bytes())
	if err != nil {
		t.Fatalf("decode #2: %v", err)
	}
	if !bytes.Equal(img1.Pix, img2.Pix) {
		t.Fatalf("PNG re-decode altered pixels: not lossless")
	}
	if img1.Stride != img2.Stride || !img1.Rect.Eq(img2.Rect) {
		t.Fatalf("PNG re-decode altered geometry")
	}

	// And extraction still recovers the body from the re-encoded bytes.
	got, err := Extract(staticCallback(shared), buf.Bytes())
	if err != nil {
		t.Fatalf("Extract after re-encode: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch after lossless re-encode")
	}
}

func TestExtractRejectsBadInputs(t *testing.T) {
	shared := fixedShared()
	epk := fixedEpk()
	pngBytes, err := Embed(shared, epk, []byte("hi"))
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	t.Run("nil_callback", func(t *testing.T) {
		if _, err := Extract(nil, pngBytes); err == nil {
			t.Fatal("expected error for nil callback")
		}
	})

	t.Run("not_a_png", func(t *testing.T) {
		if _, err := Extract(staticCallback(shared), []byte("not a png")); !errors.Is(err, errMalformed) {
			t.Fatalf("expected errMalformed, got %v", err)
		}
	})

	t.Run("callback_error", func(t *testing.T) {
		cb := func([]byte) ([]byte, error) { return nil, errors.New("no agreement") }
		if _, err := Extract(cb, pngBytes); !errors.Is(err, errMalformed) {
			t.Fatalf("expected errMalformed, got %v", err)
		}
	})

	t.Run("callback_wrong_secret_length", func(t *testing.T) {
		cb := func([]byte) ([]byte, error) { return []byte("short"), nil }
		if _, err := Extract(cb, pngBytes); !errors.Is(err, errMalformed) {
			t.Fatalf("expected errMalformed, got %v", err)
		}
	})

	t.Run("tiny_image", func(t *testing.T) {
		// A valid 1x1 PNG is far below the bootstrap region and must be rejected.
		small := image.NewNRGBA(image.Rect(0, 0, 1, 1))
		var buf bytes.Buffer
		if err := png.Encode(&buf, small); err != nil {
			t.Fatalf("encode small: %v", err)
		}
		if _, err := Extract(staticCallback(shared), buf.Bytes()); !errors.Is(err, errMalformed) {
			t.Fatalf("expected errMalformed for tiny image, got %v", err)
		}
	})
}

func TestEmbedRejectsBadArgs(t *testing.T) {
	tests := []struct {
		name   string
		shared []byte
		epk    []byte
	}{
		{"short_shared", make([]byte, 16), fixedEpk()},
		{"long_shared", make([]byte, 64), fixedEpk()},
		{"short_epk", fixedShared(), make([]byte, 16)},
		{"long_epk", fixedShared(), make([]byte, 33)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Embed(tc.shared, tc.epk, []byte("x")); err == nil {
				t.Fatal("expected error for bad argument sizes")
			}
		})
	}
}

// TestStreamUniformInRange checks that uniform stays in range and that the
// distribution over a large deterministic sample is close to uniform. The
// per-bucket +/-10% tolerance is tight enough to catch a stream whose leading
// output is biased (e.g. the old pos:0 bug that returned ~1024 leading zero
// bytes, forcing early draws into low buckets), yet the sample is large enough
// (1,000,000 draws over 10 buckets, fixed seed) that a correct ChaCha20
// keystream never trips it.
func TestStreamUniformInRange(t *testing.T) {
	s, err := newStream(fixedShared(), positionInfo)
	if err != nil {
		t.Fatalf("newStream: %v", err)
	}
	const n = 10
	counts := make([]int, n)
	const iter = 1000000
	for i := 0; i < iter; i++ {
		v := s.uniform(n)
		if v < 0 || v >= n {
			t.Fatalf("uniform out of range: %d", v)
		}
		counts[v]++
	}
	// Each bucket should be close to iter/n. With a fixed seed and 1e6 draws
	// the observed deviation of a correct stream is well under 10%, so a
	// +/-10% band is deterministic and non-flaky while still rejecting the
	// leading-zero bias of the old bug.
	expect := iter / n
	const tolerance = 0.10
	low := int(float64(expect) * (1 - tolerance))
	high := int(float64(expect) * (1 + tolerance))
	for i, c := range counts {
		if c < low || c > high {
			t.Fatalf("bucket %d skewed: %d (expect ~%d, allowed [%d,%d])", i, c, expect, low, high)
		}
	}
	// A chi-square goodness-of-fit statistic against the uniform expectation
	// gives a second, independent guard. For 9 degrees of freedom the 99.9%
	// critical value is ~27.88; a correct stream stays far below it, while a
	// stream with the leading-zero bias piles counts into low buckets and
	// blows past it.
	var chiSq float64
	for _, c := range counts {
		d := float64(c - expect)
		chiSq += d * d / float64(expect)
	}
	const chiSqCritical = 27.88 // df=9, alpha=0.001
	if chiSq > chiSqCritical {
		t.Fatalf("distribution not uniform: chi-square %.2f exceeds %.2f", chiSq, chiSqCritical)
	}
	// uniform(1) is always 0; uniform(0) defensively returns 0.
	if s.uniform(1) != 0 || s.uniform(0) != 0 {
		t.Fatal("uniform edge cases wrong")
	}
}

// TestStreamFirstBlockNotZero pins the newStream fix: the very first bytes of
// the keystream must be real ChaCha20 output, not the zero-filled scratch
// buffer. Under the old pos:0 code the first 4096 bytes were returned as
// literal zeros, so this test would fail; with pos:len(buf) the first nextByte
// forces a refill and the leading bytes match a freshly-initialized cipher.
func TestStreamFirstBlockNotZero(t *testing.T) {
	shared := fixedShared()
	s, err := newStream(shared, positionInfo)
	if err != nil {
		t.Fatalf("newStream: %v", err)
	}

	const nBytes = 64
	got := make([]byte, nBytes)
	for i := range got {
		got[i] = s.nextByte()
	}

	// Guard #1: the leading keystream must not be all zeros (the old bug).
	if allZero(got) {
		t.Fatalf("first %d keystream bytes are all zero: newStream returned the zero scratch buffer", nBytes)
	}

	// Guard #2: the leading keystream must equal the output of an independently
	// constructed cipher using the same HKDF-derived key and zero nonce over
	// nBytes of zeros. This pins the exact bytes, so a stream that skipped or
	// mangled the first block would still be caught.
	want := expectedKeystream(t, shared, positionInfo, nBytes)
	if !bytes.Equal(got, want) {
		t.Fatalf("first %d keystream bytes mismatch:\n got  %x\n want %x", nBytes, got, want)
	}
}

// allZero reports whether every byte in b is zero.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// expectedKeystream independently derives the ChaCha20 keystream for the given
// shared secret and info label, mirroring newStream's key derivation without
// reusing its buffering logic, so it can serve as an oracle for the first
// bytes out of newStream.
func expectedKeystream(t *testing.T, shared []byte, info string, n int) []byte {
	t.Helper()
	key, err := hkdf.Key(sha256.New, shared, nil, info, seedSize)
	if err != nil {
		t.Fatalf("hkdf.Key: %v", err)
	}
	nonce := make([]byte, chacha20.NonceSize)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Fatalf("NewUnauthenticatedCipher: %v", err)
	}
	out := make([]byte, n)
	c.XORKeyStream(out, out)
	return out
}

// TestFrameHeaderShape locks the on-wire header framing.
func TestFrameHeaderShape(t *testing.T) {
	frame := buildFrame([]byte("body"))
	if frame[0] != 'S' || frame[1] != 'F' || frame[2] != headerVersion {
		t.Fatalf("bad magic/version: %x", frame[:3])
	}
	if got := binary.BigEndian.Uint64(frame[3:11]); got != 4 {
		t.Fatalf("body_length = %d, want 4", got)
	}
	if string(frame[headerFixedSize:]) != "body" {
		t.Fatalf("body not appended")
	}
}
