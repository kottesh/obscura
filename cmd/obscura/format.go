package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
)

// humanBytes renders a byte count in a compact, human-readable form using SI
// (1000-based) units to match the spec's "24.8 kB" style card details (spec
// 8.2). It is display-only and never used for size enforcement.
func humanBytes(n int) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := int64(n) / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"kB", "MB", "GB", "TB", "PB"}[exp]
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), suffix)
}

// shortHex renders the first few bytes of an id as a shortened hex string with
// an ellipsis, matching the spec's "7fc84a…" receiver rendering (spec 8.2). It
// only ever shows a public user-id tag, never key or plaintext material.
func shortHex(b []byte) string {
	const show = 3 // 3 bytes -> 6 hex chars
	if len(b) > show {
		b = b[:show]
	}
	return hex.EncodeToString(b) + "…"
}

// baseName returns the final path element used as a display label. It is
// display-only; a receiver never trusts a display name as a filesystem path
// (spec 3.1).
func baseName(path string) string {
	return filepath.Base(path)
}
