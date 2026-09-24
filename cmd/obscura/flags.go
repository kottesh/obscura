package main

import (
	"flag"
	"io"
	"strings"

	"github.com/kottesh/obscura/internal/ui"
)

// newFlagSet builds a per-command flag.FlagSet that never writes usage to the
// process streams (it discards output and defers usage handling to the CLI's
// own usage errors) and returns parse failures as errors instead of exiting.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseCmd parses a subcommand's flags and validates the positional argument
// count, mapping any failure to a usageError so run selects the usage exit code
// and prints to stderr. minArgs and maxArgs bound the positional count;
// maxArgs < 0 means unbounded.
//
// The Go flag package stops parsing at the first non-flag token, but several
// subcommands take a leading positional (e.g. "send <path> --to <addr>").
// permuteArgs reorders tokens so every flag precedes the positionals before
// Parse, giving GNU-style interspersed flags without changing flag semantics.
func parseCmd(fs *flag.FlagSet, args []string, minArgs, maxArgs int) error {
	ordered, err := permuteArgs(fs, args)
	if err != nil {
		return err
	}
	if err := fs.Parse(ordered); err != nil {
		return usagef("%s: %v", fs.Name(), err)
	}
	n := fs.NArg()
	if n < minArgs {
		return usagef("%s: expected at least %d argument(s), got %d", fs.Name(), minArgs, n)
	}
	if maxArgs >= 0 && n > maxArgs {
		return usagef("%s: expected at most %d argument(s), got %d", fs.Name(), maxArgs, n)
	}
	return nil
}

// boolFlag is implemented by flag values that take no argument (e.g. bool
// flags), matching the unexported interface the flag package uses internally.
type boolFlag interface {
	IsBoolFlag() bool
}

// permuteArgs reorders args so all recognized flags (and their values) come
// before positional arguments, enabling flags to appear after a leading
// positional. It consults fs to decide whether a flag consumes the following
// token. A "--" terminator stops flag scanning; everything after it is
// positional. Unknown flags are left in place so fs.Parse reports them.
func permuteArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			i++
			continue
		}

		name := strings.TrimLeft(a, "-")
		inlineVal := false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
			inlineVal = true
		}

		def := fs.Lookup(name)
		if def == nil {
			// Unknown flag: leave as-is for fs.Parse to reject with a clear error.
			flags = append(flags, a)
			i++
			continue
		}

		flags = append(flags, a)
		i++
		// A non-bool flag with no inline value consumes the next token.
		if !inlineVal && !isBoolFlag(def) {
			if i < len(args) {
				flags = append(flags, args[i])
				i++
			}
		}
	}
	return append(flags, positional...), nil
}

// isBoolFlag reports whether a flag takes no argument.
func isBoolFlag(f *flag.Flag) bool {
	if bf, ok := f.Value.(boolFlag); ok {
		return bf.IsBoolFlag()
	}
	return false
}

// modeJSON returns the JSON render mode; a tiny helper so command code reads as
// "if env.g.mode == modeJSON()".
func modeJSON() ui.Mode { return ui.ModeJSON }

// extractLeadingID pulls the single required leading positional (a file id) out
// of args so it is never interpreted as a flag, and returns the remaining flag
// args. This is used by receive and delete, whose file id is drawn from a
// storage alphabet that includes '-', so an id like "-abc..." must be treated
// as the positional and not as an unknown flag.
//
// It walks args left to right, consulting fs to skip recognized flags and their
// values (so "receive -o out.bin <id>" still works), and returns the first
// token that is not a recognized flag (or the flag value being consumed) as the
// id. A "--" terminator forces the next token to be the id. Recognized flags
// (before and after the id) are preserved in order in the returned rest slice
// for the normal parser. If no id token is found, id is empty and the caller's
// count validation reports the usage error.
func extractLeadingID(fs *flag.FlagSet, args []string) (id string, rest []string) {
	rest = make([]string, 0, len(args))
	i := 0
	found := false
	for i < len(args) {
		a := args[i]
		if !found && a == "--" {
			// Everything after "--" is positional; the first is the id.
			if i+1 < len(args) {
				id = args[i+1]
				rest = append(rest, args[i+2:]...)
			}
			return id, rest
		}
		name, _, hasInline := splitFlag(a)
		trimmed := strings.TrimLeft(name, "-")
		if def := fs.Lookup(trimmed); strings.HasPrefix(a, "-") && def != nil {
			// A recognized flag: keep it, and consume its value token when it
			// takes one and has no inline "=value".
			rest = append(rest, a)
			i++
			if !hasInline && !isBoolFlag(def) && i < len(args) {
				rest = append(rest, args[i])
				i++
			}
			continue
		}
		if !found {
			// First non-recognized-flag token is the id (even if it starts '-').
			id = a
			found = true
			i++
			continue
		}
		// Any further tokens are left for the parser to report (extra args or
		// unknown flags).
		rest = append(rest, a)
		i++
	}
	return id, rest
}
