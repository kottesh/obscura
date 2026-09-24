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
