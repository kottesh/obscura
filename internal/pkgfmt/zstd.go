package pkgfmt

import (
	"crypto/subtle"

	"github.com/klauspost/compress/zstd"
)

// zstdEncoder and zstdDecoder are shared, concurrency-safe instances. The
// decoder uses WithDecodeAllCapLimit(true) so that DecodeAll never writes more
// bytes than the destination buffer's spare capacity (see decompressBounded).
// WithDecoderConcurrency(1) keeps memory predictable for many small decodes.
var (
	zstdEncoder = mustEncoder()
	zstdDecoder = mustDecoder()
)

func mustEncoder() *zstd.Encoder {
	e, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		panic("pkgfmt: init zstd encoder: " + err.Error())
	}
	return e
}

func mustDecoder() *zstd.Decoder {
	d, err := zstd.NewReader(nil,
		zstd.WithDecodeAllCapLimit(true),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(DefaultMaxOriginalSize),
	)
	if err != nil {
		panic("pkgfmt: init zstd decoder: " + err.Error())
	}
	return d
}

// compress returns the Zstandard-compressed form of payload.
func compress(payload []byte) []byte {
	return zstdEncoder.EncodeAll(payload, nil)
}

// decompressBounded decompresses src to exactly originalSize bytes. The
// destination buffer is pre-sized to originalSize and, combined with the
// decoder's WithDecodeAllCapLimit(true), hard-caps DecodeAll output so a
// decompression bomb (small compressed, huge claimed original_size) cannot
// exhaust memory. It rejects any output whose length differs from originalSize.
func decompressBounded(src []byte, originalSize uint64) ([]byte, error) {
	if originalSize > DefaultMaxOriginalSize {
		return nil, errOriginalTooBig
	}
	// dst has len 0 and cap originalSize; WithDecodeAllCapLimit bounds DecodeAll
	// to cap(dst)-len(dst) = originalSize bytes and errors if more is produced.
	dst := make([]byte, 0, originalSize)
	out, err := zstdDecoder.DecodeAll(src, dst)
	if err != nil {
		return nil, errDecompress
	}
	if uint64(len(out)) != originalSize {
		return nil, errSizeMismatch
	}
	return out, nil
}

// subtleEqual reports whether a and b are equal in constant time.
func subtleEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
