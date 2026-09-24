// Package ui implements the Obscura terminal output contract described in the
// system specification (section 8). It renders compact notification cards to a
// caller-supplied writer that is stderr by convention. The renderer never
// writes to stdout: command results and raw bytes belong on stdout and are the
// caller's responsibility, while progress cards and diagnostics go here.
//
// A card is a colored left border followed by a bold title and one or more
// muted detail lines. Color and border decoration are enabled only when the
// output target is a terminal, TERM is not "dumb", NO_COLOR is unset, and the
// renderer is not in no-color or JSON mode. In every other case the renderer
// emits plain, ANSI-free text so redirected or piped output is never corrupted.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// Semantic colors from spec section 8.1. Each meaning maps to one hex value so
// that cards stay visually consistent across the CLI.
const (
	// ColorCommand marks command/SSH activity.
	ColorCommand = lipgloss.Color("#65adff")
	// ColorSuccess marks a successfully committed operation.
	ColorSuccess = lipgloss.Color("#6fcc85")
	// ColorFailure marks an error or failed operation.
	ColorFailure = lipgloss.Color("#ff7079")
	// ColorCrypto marks cryptographic and verification steps.
	ColorCrypto = lipgloss.Color("#11d4b7")
	// ColorWarning marks warnings and confirmations.
	ColorWarning = lipgloss.Color("#f5b41d")
	// ColorMuted marks secondary metadata such as detail lines.
	ColorMuted = lipgloss.Color("#868a91")
)

// borderChar is the left border glyph used on every decorated card, matching
// the spec examples in section 8.1.
const borderChar = "┃"

// Mode selects how the renderer decorates and whether it emits cards at all.
type Mode int

const (
	// ModeNormal renders decorated cards when the target supports them and
	// plain cards otherwise.
	ModeNormal Mode = iota
	// ModeQuiet suppresses progress, stage, and success cards but still emits
	// failure and warning cards so errors remain visible (spec 8.4 --quiet).
	ModeQuiet
	// ModeNoColor renders plain text cards with no ANSI escapes (spec 8.4
	// --no-color).
	ModeNoColor
	// ModeJSON disables all cards; the CLI emits a single versioned JSON value
	// to stdout itself (spec 8.3 and 8.4 --json).
	ModeJSON
)

// Renderer writes notification cards to a single writer, which is stderr by
// convention. The renderer only ever holds this one writer and never reaches
// for os.Stdout, enforcing the stream discipline in spec 8.3.
type Renderer struct {
	w     io.Writer
	mode  Mode
	color bool // whether ANSI color/border decoration is enabled

	borderStyle lipgloss.Style
	titleStyle  lipgloss.Style
	detailStyle lipgloss.Style
}

// New constructs a Renderer for production use. The writer target is stderr by
// convention. The target file (used only for TTY detection) and environment
// lookup decide whether decoration is enabled. Color and border decoration are
// enabled only when mode is ModeNormal, target is a terminal, TERM != "dumb",
// and NO_COLOR is unset (spec 8.4). ModeNoColor, ModeQuiet, and ModeJSON never
// emit ANSI escapes.
//
// target may be nil, in which case decoration is disabled. Passing the same
// *os.File as both writer and target is the common case (os.Stderr).
func New(w io.Writer, target *os.File, mode Mode, getenv func(string) string) *Renderer {
	if getenv == nil {
		getenv = os.Getenv
	}
	color := decideColor(target, mode, getenv)
	return newRenderer(w, mode, color)
}

// NewForFile is a convenience constructor that renders to the given *os.File
// and uses it as the TTY-detection target with the process environment.
func NewForFile(f *os.File, mode Mode) *Renderer {
	return New(f, f, mode, os.Getenv)
}

// NewForTest constructs a Renderer with an explicit writer, mode, and color
// decision. It performs no TTY or environment inspection, so tests get a
// deterministic renderer.
func NewForTest(w io.Writer, mode Mode, color bool) *Renderer {
	// JSON and quiet modes never decorate, and no-color forces plain output,
	// so tests cannot accidentally request color in a mode that forbids it.
	if mode == ModeJSON || mode == ModeNoColor {
		color = false
	}
	return newRenderer(w, mode, color)
}

func newRenderer(w io.Writer, mode Mode, color bool) *Renderer {
	r := &Renderer{w: w, mode: mode, color: color}
	if color {
		// Build styles on a renderer with an explicitly forced color profile so
		// ANSI escapes are emitted regardless of the writer's detected terminal
		// capabilities. Whether to decorate at all is already decided upstream by
		// decideColor, so once we are here we always want escapes.
		lr := lipgloss.NewRenderer(io.Discard)
		lr.SetColorProfile(termenv.TrueColor)
		r.borderStyle = lr.NewStyle()
		r.titleStyle = lr.NewStyle().Bold(true)
		r.detailStyle = lr.NewStyle().Foreground(ColorMuted)
	}
	return r
}

// decideColor implements the TTY/automation rules from spec 8.4.
func decideColor(target *os.File, mode Mode, getenv func(string) string) bool {
	if mode != ModeNormal {
		return false
	}
	if getenv("NO_COLOR") != "" {
		return false
	}
	if getenv("TERM") == "dumb" {
		return false
	}
	if target == nil {
		return false
	}
	return term.IsTerminal(int(target.Fd()))
}

// ProgressEnabled reports whether the renderer emits progress and stage cards.
// The CLI uses it to skip building progress details when nothing would be
// shown. Progress is disabled in quiet and JSON modes (spec 8.3 and 8.4).
func (r *Renderer) ProgressEnabled() bool {
	return r.mode != ModeQuiet && r.mode != ModeJSON
}

// ColorEnabled reports whether ANSI color/border decoration is active.
func (r *Renderer) ColorEnabled() bool {
	return r.color
}

// Stage renders an in-progress stage card in the command/SSH color. It is
// suppressed in quiet and JSON modes.
func (r *Renderer) Stage(title, detail string) {
	if !r.ProgressEnabled() {
		return
	}
	r.card(ColorCommand, title, detail)
}

// Crypto renders a cryptographic/verification stage card. It is suppressed in
// quiet and JSON modes.
func (r *Renderer) Crypto(title, detail string) {
	if !r.ProgressEnabled() {
		return
	}
	r.card(ColorCrypto, title, detail)
}

// Success renders a completion card in the success color. It is suppressed in
// quiet and JSON modes because it is a progress-style card.
func (r *Renderer) Success(title, detail string) {
	if !r.ProgressEnabled() {
		return
	}
	r.card(ColorSuccess, title, detail)
}

// Warn renders a warning/confirmation card. Warnings survive quiet mode because
// they carry actionable information, but JSON mode still suppresses all cards.
func (r *Renderer) Warn(title, detail string) {
	if r.mode == ModeJSON {
		return
	}
	r.card(ColorWarning, title, detail)
}

// Failure renders a failure card in the failure color. Failures survive quiet
// mode (spec 8.4: errors remain) but JSON mode suppresses all cards because the
// CLI reports the error inside its single JSON value instead.
func (r *Renderer) Failure(title, detail string) {
	if r.mode == ModeJSON {
		return
	}
	r.card(ColorFailure, title, detail)
}

// card writes one notification card to the target writer. Detail may contain
// newlines to produce multiple muted lines; empty details are omitted.
func (r *Renderer) card(color lipgloss.Color, title, detail string) {
	var b strings.Builder

	if r.color {
		border := r.borderStyle.Foreground(color).Render(borderChar)
		b.WriteString(border)
		b.WriteByte(' ')
		b.WriteString(r.titleStyle.Foreground(color).Render(title))
		b.WriteByte('\n')
		for _, line := range detailLines(detail) {
			b.WriteString(border)
			b.WriteByte(' ')
			b.WriteString(r.detailStyle.Render(line))
			b.WriteByte('\n')
		}
	} else {
		b.WriteString(borderChar)
		b.WriteByte(' ')
		b.WriteString(title)
		b.WriteByte('\n')
		for _, line := range detailLines(detail) {
			b.WriteString(borderChar)
			b.WriteByte(' ')
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	fmt.Fprint(r.w, b.String())
}

// detailLines splits a detail string into non-empty lines. A wholly empty
// detail yields no lines so the card shows only its title.
func detailLines(detail string) []string {
	if detail == "" {
		return nil
	}
	return strings.Split(detail, "\n")
}
