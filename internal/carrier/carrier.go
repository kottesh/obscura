// Package carrier implements the optional PNG steganography carrier described
// in the Obscura system specification, section 4. It hides an already
// encrypted, opaque package inside a freshly generated lossless PNG using RGB
// LSB matching at positions derived from a shared X25519 secret.
//
// The carrier is deliberately independent of the package format layer: it
// operates on opaque package bytes plus the sender/receiver X25519 material.
// Callers supply the shared secret and the ephemeral public key directly (for
// embedding) or a key-agreement callback (for extraction), so this package
// never imports the package-format or identity layers.
//
// Embedding layout (spec 4.3):
//
//	bootstrap: E_pk (32 bytes) in reserved RGB slots [0,256)
//	header:    magic "SF" || version || body_length (11 bytes)
//	body:      opaque package bytes, at positions derived from a shuffle of the
//	           eligible slots [256,total)
//
// Both bootstrap and payload are embedded one bit per logical RGB slot via LSB
// matching. Alpha bytes are never modified.
package carrier

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"

	"golang.org/x/crypto/chacha20"
)

// HKDF info labels for the position and matching streams. These labels are
// part of the on-wire contract and must not change without a version bump.
const (
	positionInfo = "obscura/stego-positions/v1"
	matchingInfo = "obscura/stego-matching/v1"
)

// seedSize is the length of each derived stream seed.
const seedSize = 32

// epkSize is the length of the ephemeral X25519 public key stored in the
// bootstrap region.
const epkSize = 32

// bootstrapSlots is the number of reserved logical RGB slots used to store
// E_pk. 32 bytes * 8 bits = 256 bits, one bit per slot.
const bootstrapSlots = epkSize * 8

// header framing constants (spec 4.3).
const (
	headerMagic0    = 'S'
	headerMagic1    = 'F'
	headerVersion   = 0x01
	headerLenBytes  = 8 // big-endian uint64 body_length
	headerFixedSize = 2 + 1 + headerLenBytes
)

// maxBodyLen bounds the declared body length in an extracted header to reject
// oversized allocations from malformed input. 1 GiB is far above any expected
// encrypted package and well below the carrier capacity of any realistically
// generatable PNG.
const maxBodyLen = 1 << 30

// bodySlotFraction limits payload use to at most 50% of the eligible slots per
// spec 4.2 ("Body use is limited to 50% of eligible slots"). Header and body
// share this budget since both are embedded in the shuffled eligible region.
const bodySlotFraction = 2 // divide eligible count by this

// A generic error is returned for all malformed-input cases so extraction does
// not reveal whether framing, positions, or bounds were the exact cause.
var errMalformed = errors.New("carrier: malformed or corrupt PNG carrier")

// Embed hides packageBody inside a freshly generated lossless PNG using RGB LSB
// matching at positions derived from sharedSecret. ephemeralPub (E_pk) is
// stored verbatim in the reserved bootstrap slots so an extractor can recover
// the shared secret via key agreement.
//
// sharedSecret must be the 32-byte X25519 shared secret; ephemeralPub must be
// the 32-byte ephemeral public key. The returned bytes are a complete PNG.
func Embed(sharedSecret []byte, ephemeralPub []byte, packageBody []byte) ([]byte, error) {
	if len(sharedSecret) != seedSize {
		return nil, fmt.Errorf("carrier: shared secret must be %d bytes, got %d", seedSize, len(sharedSecret))
	}
	if len(ephemeralPub) != epkSize {
		return nil, fmt.Errorf("carrier: ephemeral pub must be %d bytes, got %d", epkSize, len(ephemeralPub))
	}

	// payload = header || body, embedded in the eligible (shuffled) region.
	payload := buildFrame(packageBody)
	payloadSlots := len(payload) * 8

	width, height, err := planImage(payloadSlots)
	if err != nil {
		return nil, err
	}

	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	// Fill with an opaque mid-gray cover so every channel can move +/-1 without
	// clamping and alpha is a constant 0xff we never touch.
	fillCover(img)

	positions, err := derivePositions(sharedSecret, img.Rect.Dx(), img.Rect.Dy())
	if err != nil {
		return nil, err
	}
	matching, err := newStream(sharedSecret, matchingInfo)
	if err != nil {
		return nil, err
	}

	// Bootstrap: E_pk bits into the reserved slots [0,256) in slot order.
	epkBits := bitsOf(ephemeralPub)
	for i, bit := range epkBits {
		matchSlot(img, i, bit, matching)
	}

	// Payload: header || body into the shuffled eligible slots.
	payloadBits := bitsOf(payload)
	if len(payloadBits) > len(positions) {
		// planImage guarantees capacity, but guard against arithmetic drift.
		return nil, fmt.Errorf("carrier: payload %d bits exceeds %d eligible slots", len(payloadBits), len(positions))
	}
	for i, bit := range payloadBits {
		matchSlot(img, positions[i], bit, matching)
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("carrier: encode png: %w", err)
	}
	return buf.Bytes(), nil
}

// Extract recovers the opaque package body from a PNG produced by Embed. It
// reads E_pk from the bootstrap slots, calls sharedSecretFromEpk to derive the
// shared secret, re-derives the positions, validates the bounded "SF" header,
// and returns the body. All malformed input yields a single generic error.
func Extract(sharedSecretFromEpk func(epk []byte) ([]byte, error), pngBytes []byte) ([]byte, error) {
	if sharedSecretFromEpk == nil {
		return nil, errors.New("carrier: nil key-agreement callback")
	}

	img, err := decodeNRGBA(pngBytes)
	if err != nil {
		return nil, errMalformed
	}
	width := img.Rect.Dx()
	height := img.Rect.Dy()
	totalSlots := width * height * 3
	if totalSlots < bootstrapSlots {
		return nil, errMalformed
	}

	// Bootstrap: read E_pk from the reserved slots [0,256) in slot order.
	epk := make([]byte, epkSize)
	for i := 0; i < bootstrapSlots; i++ {
		off, ok := slotOffset(img, i)
		if !ok {
			return nil, errMalformed
		}
		if img.Pix[off]&1 == 1 {
			epk[i/8] |= 1 << (7 - uint(i%8))
		}
	}

	shared, err := sharedSecretFromEpk(epk)
	if err != nil {
		return nil, errMalformed
	}
	if len(shared) != seedSize {
		return nil, errMalformed
	}

	positions, err := derivePositions(shared, width, height)
	if err != nil {
		return nil, errMalformed
	}

	// Read the fixed header first, then the declared body.
	if headerFixedSize*8 > len(positions) {
		return nil, errMalformed
	}
	header := readBytes(img, positions, 0, headerFixedSize)
	if header[0] != headerMagic0 || header[1] != headerMagic1 {
		return nil, errMalformed
	}
	if header[2] != headerVersion {
		return nil, errMalformed
	}
	bodyLen := binary.BigEndian.Uint64(header[3 : 3+headerLenBytes])
	if bodyLen > maxBodyLen {
		return nil, errMalformed
	}
	totalBits := (headerFixedSize + int(bodyLen)) * 8
	if bodyLen > uint64(len(positions)/8) || totalBits > len(positions) {
		return nil, errMalformed
	}

	body := readBytes(img, positions, headerFixedSize, int(bodyLen))
	return body, nil
}

// buildFrame concatenates the fixed header and the body into the payload that
// occupies the eligible slot region.
func buildFrame(body []byte) []byte {
	frame := make([]byte, headerFixedSize+len(body))
	frame[0] = headerMagic0
	frame[1] = headerMagic1
	frame[2] = headerVersion
	binary.BigEndian.PutUint64(frame[3:3+headerLenBytes], uint64(len(body)))
	copy(frame[headerFixedSize:], body)
	return frame
}

// planImage computes an image large enough that the shuffled eligible region
// holds payloadSlots bits within the 50% body-use budget, and returns its
// width and height. It rejects sizes whose slot arithmetic would overflow.
func planImage(payloadSlots int) (width, height int, err error) {
	if payloadSlots < 0 {
		return 0, 0, errors.New("carrier: negative payload size")
	}

	// eligibleNeeded is the number of eligible slots the payload must fit into
	// at 50% use: payloadSlots <= eligible/2  =>  eligible >= 2*payloadSlots.
	if payloadSlots > (maxInt-1)/bodySlotFraction {
		return 0, 0, errors.New("carrier: payload too large for carrier capacity")
	}
	eligibleNeeded := payloadSlots * bodySlotFraction

	// totalSlots = bootstrap + eligible. Must not overflow.
	if eligibleNeeded > maxInt-bootstrapSlots {
		return 0, 0, errors.New("carrier: payload too large for carrier capacity")
	}
	totalSlotsNeeded := bootstrapSlots + eligibleNeeded

	// Each pixel provides 3 slots (RGB). Round pixels up.
	pixelsNeeded := (totalSlotsNeeded + 2) / 3
	if pixelsNeeded < 1 {
		pixelsNeeded = 1
	}

	// Choose a near-square image so width and height stay modest. width =
	// ceil(sqrt(pixels)).
	width = isqrtCeil(pixelsNeeded)
	if width < 1 {
		width = 1
	}
	height = (pixelsNeeded + width - 1) / width
	if height < 1 {
		height = 1
	}

	// Final overflow / capacity sanity check on the concrete dimensions.
	if width > maxInt/height {
		return 0, 0, errors.New("carrier: image dimensions overflow")
	}
	pixels := width * height
	if pixels > maxInt/3 {
		return 0, 0, errors.New("carrier: image slot count overflow")
	}
	total := pixels * 3
	if total-bootstrapSlots < eligibleNeeded {
		return 0, 0, errors.New("carrier: insufficient carrier capacity")
	}
	return width, height, nil
}

// fillCover paints an opaque mid-gray cover so LSB matching can move any
// channel +/-1 without clamping and alpha stays a constant 0xff.
func fillCover(img *image.NRGBA) {
	gray := color.NRGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xff}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			img.SetNRGBA(x, y, gray)
		}
	}
}

// slotOffset maps a logical RGB slot to a byte offset into img.Pix per spec
// 4.2. It never returns an alpha byte and returns ok=false for out-of-range
// slots.
func slotOffset(img *image.NRGBA, slot int) (int, bool) {
	if slot < 0 {
		return 0, false
	}
	width := img.Rect.Dx()
	height := img.Rect.Dy()
	if width <= 0 || height <= 0 {
		return 0, false
	}
	pixel := slot / 3
	ch := slot % 3
	if pixel >= width*height {
		return 0, false
	}
	x := pixel % width
	y := pixel / width
	off := y*img.Stride + x*4 + ch
	if off < 0 || off >= len(img.Pix) {
		return 0, false
	}
	return off, true
}

// matchSlot applies LSB matching to the channel byte at the given slot so its
// least significant bit equals bit. When the parity must change, it moves the
// byte +1 or -1 chosen from the matching stream, clamping only at the 0/255
// boundaries. Alpha bytes are never addressed by slotOffset.
func matchSlot(img *image.NRGBA, slot int, bit byte, matching *stream) {
	off, ok := slotOffset(img, slot)
	if !ok {
		return
	}
	v := img.Pix[off]
	if v&1 == bit&1 {
		return
	}
	// Parity must flip. Choose +1 or -1 from the matching stream.
	if v == 0 {
		v = 1
	} else if v == 255 {
		v = 254
	} else if matching.bit() == 1 {
		v++
	} else {
		v--
	}
	img.Pix[off] = v
}

// readBytes reads count bytes starting at byte index start within the payload
// region (positions), returning them MSB-first per byte.
func readBytes(img *image.NRGBA, positions []int, start, count int) []byte {
	out := make([]byte, count)
	base := start * 8
	for i := 0; i < count*8; i++ {
		off, ok := slotOffset(img, positions[base+i])
		if !ok {
			continue
		}
		if img.Pix[off]&1 == 1 {
			out[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return out
}

// bitsOf expands b into MSB-first bits.
func bitsOf(b []byte) []byte {
	bits := make([]byte, len(b)*8)
	for i, by := range b {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (by >> (7 - uint(j))) & 1
		}
	}
	return bits
}

// derivePositions returns a permutation of the eligible slots [256,total) via a
// ChaCha20-driven Fisher-Yates shuffle with rejection sampling, seeded from the
// position stream. The bootstrap slots [0,256) are never included.
func derivePositions(sharedSecret []byte, width, height int) ([]int, error) {
	total := width * height * 3
	if total < bootstrapSlots {
		return nil, errors.New("carrier: image too small for bootstrap region")
	}
	eligible := total - bootstrapSlots
	perm := make([]int, eligible)
	for i := range perm {
		perm[i] = bootstrapSlots + i
	}

	s, err := newStream(sharedSecret, positionInfo)
	if err != nil {
		return nil, err
	}
	// Fisher-Yates: for i from n-1 down to 1, swap perm[i] with perm[j],
	// j uniform in [0,i] via rejection sampling on the ChaCha20 stream.
	for i := eligible - 1; i > 0; i-- {
		j := s.uniform(uint32(i + 1))
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm, nil
}

// stream is a ChaCha20 keystream reader used for position shuffling and match
// direction. The keystream is generated by XORing zeros, giving deterministic
// pseudo-random bytes from the seed.
type stream struct {
	c   *chacha20.Cipher
	buf []byte
	pos int
	// bitBuf/bitCount hold leftover bits for bit().
	bitBuf   byte
	bitCount int
}

// newStream builds a keystream from HKDF-SHA256(sharedSecret, nil, info, 32)
// used as the ChaCha20 key with a fixed zero nonce.
func newStream(sharedSecret []byte, info string) (*stream, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, info, seedSize)
	if err != nil {
		return nil, fmt.Errorf("carrier: derive %q seed: %w", info, err)
	}
	nonce := make([]byte, chacha20.NonceSize)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("carrier: init chacha20: %w", err)
	}
	// pos starts at len(buf) so the first nextByte() forces a real keystream
	// refill; otherwise the leading buffer of zero bytes would be returned as
	// keystream, biasing the position shuffle and LSB-matching decisions.
	buf := make([]byte, 4096)
	return &stream{c: c, buf: buf, pos: len(buf)}, nil
}

// nextByte returns the next keystream byte.
func (s *stream) nextByte() byte {
	if s.pos >= len(s.buf) {
		for i := range s.buf {
			s.buf[i] = 0
		}
		s.c.XORKeyStream(s.buf, s.buf)
		s.pos = 0
	}
	b := s.buf[s.pos]
	s.pos++
	return b
}

// nextUint32 returns the next big-endian uint32 from the keystream.
func (s *stream) nextUint32() uint32 {
	return uint32(s.nextByte())<<24 | uint32(s.nextByte())<<16 |
		uint32(s.nextByte())<<8 | uint32(s.nextByte())
}

// uniform returns a uniformly random value in [0,n) using rejection sampling to
// avoid modulo bias. n must be > 0.
func (s *stream) uniform(n uint32) int {
	if n == 0 {
		return 0
	}
	// Largest multiple of n that fits in uint32; reject anything at or above.
	limit := (uint32(1<<32-1) / n) * n
	for {
		v := s.nextUint32()
		if v < limit {
			return int(v % n)
		}
	}
}

// bit returns the next keystream bit (0 or 1) for LSB match direction.
func (s *stream) bit() byte {
	if s.bitCount == 0 {
		s.bitBuf = s.nextByte()
		s.bitCount = 8
	}
	b := (s.bitBuf >> 7) & 1
	s.bitBuf <<= 1
	s.bitCount--
	return b
}

// decodeNRGBA decodes PNG bytes and normalizes the result to *image.NRGBA.
func decodeNRGBA(pngBytes []byte) (*image.NRGBA, error) {
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return nil, err
	}
	if nrgba, ok := img.(*image.NRGBA); ok {
		return nrgba, nil
	}
	b := img.Bounds()
	out := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			out.Set(x, y, img.At(x, y))
		}
	}
	return out, nil
}

// maxInt is the maximum value of the platform int, used for overflow checks.
const maxInt = int(^uint(0) >> 1)

// isqrtCeil returns ceil(sqrt(n)) for n >= 0.
func isqrtCeil(n int) int {
	if n <= 1 {
		return n
	}
	r := 0
	for r*r < n {
		r++
	}
	return r
}
