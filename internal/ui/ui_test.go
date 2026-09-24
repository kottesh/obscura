package ui

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// esc is the ANSI escape byte (0x1b) that must never appear in plain output.
const esc = 0x1b

func TestCardContentAndNoANSI(t *testing.T) {
	tests := []struct {
		name   string
		call   func(r *Renderer)
		title  string
		detail string
	}{
		{
			name:   "stage",
			call:   func(r *Renderer) { r.Stage("Encrypting", "X25519 · XChaCha20-Poly1305") },
			title:  "Encrypting",
			detail: "X25519 · XChaCha20-Poly1305",
		},
		{
			name:   "success",
			call:   func(r *Renderer) { r.Success("File shared", "id: Qm8kP2xA") },
			title:  "File shared",
			detail: "id: Qm8kP2xA",
		},
		{
			name:   "warn",
			call:   func(r *Renderer) { r.Warn("Warning", "temporary output removed") },
			title:  "Warning",
			detail: "temporary output removed",
		},
		{
			name:   "failure",
			call:   func(r *Renderer) { r.Failure("Unable to decrypt", "Authentication failed.") },
			title:  "Unable to decrypt",
			detail: "Authentication failed.",
		},
		{
			name:   "crypto",
			call:   func(r *Renderer) { r.Crypto("Verifying", "BLAKE3 matched") },
			title:  "Verifying",
			detail: "BLAKE3 matched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			r := NewForTest(&buf, ModeNoColor, false)
			tt.call(r)

			out := buf.String()
			if !strings.Contains(out, tt.title) {
				t.Errorf("output missing title %q: %q", tt.title, out)
			}
			if !strings.Contains(out, tt.detail) {
				t.Errorf("output missing detail %q: %q", tt.detail, out)
			}
			if !strings.Contains(out, borderChar) {
				t.Errorf("output missing border %q: %q", borderChar, out)
			}
			if bytes.IndexByte(buf.Bytes(), esc) != -1 {
				t.Errorf("no-color output contains ANSI escape: %q", out)
			}
		})
	}
}

func TestColorModeEmitsANSI(t *testing.T) {
	tests := []struct {
		name string
		call func(r *Renderer)
	}{
		{"stage", func(r *Renderer) { r.Stage("Encrypting", "detail") }},
		{"success", func(r *Renderer) { r.Success("Done", "detail") }},
		{"warn", func(r *Renderer) { r.Warn("Warning", "detail") }},
		{"failure", func(r *Renderer) { r.Failure("Failed", "detail") }},
		{"crypto", func(r *Renderer) { r.Crypto("Verifying", "detail") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			r := NewForTest(&buf, ModeNormal, true)
			tt.call(r)

			out := buf.String()
			if bytes.IndexByte(buf.Bytes(), esc) == -1 {
				t.Errorf("color output missing ANSI escape: %q", out)
			}
			// The title text must still be present alongside the escapes.
			if !strings.Contains(out, "detail") {
				t.Errorf("color output missing detail text: %q", out)
			}
		})
	}
}

func TestQuietMode(t *testing.T) {
	var buf bytes.Buffer
	r := NewForTest(&buf, ModeQuiet, false)

	r.Stage("Encrypting", "detail")
	r.Success("File shared", "id")
	r.Crypto("Verifying", "detail")
	if buf.Len() != 0 {
		t.Errorf("quiet mode emitted progress output: %q", buf.String())
	}

	r.Failure("Unable to decrypt", "Authentication failed.")
	if buf.Len() == 0 {
		t.Error("quiet mode suppressed failure card")
	}
	if !strings.Contains(buf.String(), "Unable to decrypt") {
		t.Errorf("quiet failure missing title: %q", buf.String())
	}

	// Warnings also survive quiet mode.
	buf.Reset()
	r.Warn("Warning", "check identity")
	if buf.Len() == 0 {
		t.Error("quiet mode suppressed warning card")
	}
}

func TestJSONModeSuppressesAll(t *testing.T) {
	var buf bytes.Buffer
	r := NewForTest(&buf, ModeJSON, false)

	r.Stage("Encrypting", "detail")
	r.Success("File shared", "id")
	r.Crypto("Verifying", "detail")
	r.Warn("Warning", "detail")
	r.Failure("Unable to decrypt", "Authentication failed.")

	if buf.Len() != 0 {
		t.Errorf("JSON mode emitted card output: %q", buf.String())
	}
	if r.ProgressEnabled() {
		t.Error("JSON mode reports progress enabled")
	}
}

func TestProgressEnabled(t *testing.T) {
	tests := []struct {
		mode Mode
		want bool
	}{
		{ModeNormal, true},
		{ModeNoColor, true},
		{ModeQuiet, false},
		{ModeJSON, false},
	}
	for _, tt := range tests {
		r := NewForTest(&bytes.Buffer{}, tt.mode, false)
		if got := r.ProgressEnabled(); got != tt.want {
			t.Errorf("mode %d: ProgressEnabled()=%v, want %v", tt.mode, got, tt.want)
		}
	}
}

func TestDecideColor(t *testing.T) {
	// env builds a getenv func from a fixed map.
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	tests := []struct {
		name   string
		mode   Mode
		target bool // whether to pass a *os.File target (non-terminal pipe)
		env    map[string]string
		want   bool
	}{
		{
			name:   "non-terminal writer disables color",
			mode:   ModeNormal,
			target: true, // a pipe file, which is not a terminal
			env:    map[string]string{"TERM": "xterm-256color"},
			want:   false,
		},
		{
			name:   "nil target disables color",
			mode:   ModeNormal,
			target: false,
			env:    map[string]string{"TERM": "xterm-256color"},
			want:   false,
		},
		{
			name:   "NO_COLOR set disables color",
			mode:   ModeNormal,
			target: true,
			env:    map[string]string{"TERM": "xterm-256color", "NO_COLOR": "1"},
			want:   false,
		},
		{
			name:   "TERM=dumb disables color",
			mode:   ModeNormal,
			target: true,
			env:    map[string]string{"TERM": "dumb"},
			want:   false,
		},
		{
			name:   "no-color mode disables color",
			mode:   ModeNoColor,
			target: true,
			env:    map[string]string{"TERM": "xterm-256color"},
			want:   false,
		},
		{
			name:   "json mode disables color",
			mode:   ModeJSON,
			target: true,
			env:    map[string]string{"TERM": "xterm-256color"},
			want:   false,
		},
		{
			name:   "quiet mode disables color",
			mode:   ModeQuiet,
			target: true,
			env:    map[string]string{"TERM": "xterm-256color"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use an os.Pipe read end as a real *os.File that is not a TTY, so
			// term.IsTerminal returns false and we exercise the non-terminal
			// branch without touching the package directory or CWD.
			var target *os.File
			if tt.target {
				pr, pw, err := os.Pipe()
				if err != nil {
					t.Fatalf("pipe: %v", err)
				}
				t.Cleanup(func() { pr.Close(); pw.Close() })
				target = pr
			}
			got := decideColor(target, tt.mode, env(tt.env))
			if got != tt.want {
				t.Errorf("decideColor()=%v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewUsesStderrTargetPlain confirms that New with a non-terminal writer
// produces plain output (no ANSI), matching the stream-discipline rule.
func TestNewPlainForNonTerminal(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	var buf bytes.Buffer
	// target is the pipe write end (not a terminal); writer is a buffer.
	r := New(&buf, pw, ModeNormal, func(string) string { return "" })
	if r.ColorEnabled() {
		t.Error("expected color disabled for non-terminal target")
	}
	r.Stage("Encrypting", "detail")
	if bytes.IndexByte(buf.Bytes(), esc) != -1 {
		t.Errorf("non-terminal target produced ANSI: %q", buf.String())
	}
}
