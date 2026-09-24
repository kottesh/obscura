package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/kottesh/obscura/internal/keystore"
	"github.com/kottesh/obscura/internal/sshclient"
	"github.com/kottesh/obscura/internal/ui"
)

// exit codes for the process (spec 6.3 / 8). Zero is success; every failure is
// non-zero. usageError and other failures map to exitFailure unless the failure
// is a well-known typed error mapped to a more specific human message.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// usageError marks an argument/usage failure so run can pick the usage exit
// code and print a usage-style message to stderr.
type usageError struct {
	msg string
}

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// run is the testable entry point. It parses global flags and the subcommand,
// dispatches, and converts any error into a process exit code. It never panics
// to the user: a deferred recover converts an unexpected panic into a failure
// exit. All progress and errors go to stderr; only command results go to
// stdout (spec 8.3).
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) (code int) {
	g, rest, err := parseGlobal(args, getenv)
	if err != nil {
		// No renderer yet; emit a plain usage error to stderr.
		fmt.Fprintln(stderr, "obscura:", err)
		return exitUsage
	}

	r := ui.New(stderr, stderrFile(stderr), g.mode, getenv)

	defer func() {
		if rec := recover(); rec != nil {
			// Never surface a panic/stack to the user; map to a failure exit
			// with a generic message on stderr.
			r.Failure("Internal error", "The command aborted unexpectedly.")
			code = exitFailure
		}
	}()

	if len(rest) == 0 {
		fmt.Fprintln(stderr, "obscura:", usageText)
		return exitUsage
	}

	cmd, cmdArgs := rest[0], rest[1:]

	env := &cmdEnv{
		g:      g,
		r:      r,
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		getenv: getenv,
	}

	if err := dispatch(ctx, env, cmd, cmdArgs); err != nil {
		return reportError(env, err)
	}
	return exitOK
}

// cmdEnv bundles the parsed global config, renderer, and streams passed to each
// subcommand so their signatures stay small and testable.
type cmdEnv struct {
	g      globalFlags
	r      *ui.Renderer
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
}

// dispatch routes to the subcommand implementation.
func dispatch(ctx context.Context, env *cmdEnv, cmd string, args []string) error {
	switch cmd {
	case "init":
		return cmdInit(ctx, env, args)
	case "address":
		return cmdAddress(ctx, env, args)
	case "send":
		return cmdSend(ctx, env, args)
	case "list":
		return cmdList(ctx, env, args)
	case "receive":
		return cmdReceive(ctx, env, args)
	case "delete":
		return cmdDelete(ctx, env, args)
	case "inspect":
		return cmdInspect(ctx, env, args)
	case "config":
		return cmdConfig(ctx, env, args)
	case "known-hosts":
		return cmdKnownHosts(ctx, env, args)
	case "help", "-h", "--help":
		fmt.Fprintln(env.stderr, usageText)
		return nil
	default:
		return usagef("unknown command %q\n\n%s", cmd, usageText)
	}
}

// reportError renders a failure card (unless JSON mode already reported it) and
// returns the process exit code for err. Typed sshclient and keystore errors
// map to concise, actionable messages; usage errors map to the usage exit.
func reportError(env *cmdEnv, err error) int {
	// In JSON mode, emit exactly one JSON error object to stdout and suppress
	// the stderr failure card (which ModeJSON would drop anyway), so a --json
	// consumer always receives a single structured object.
	if env.g.mode == modeJSON() {
		_ = writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"error":   errorKind(err),
			"message": errorMessage(err),
		})
		if isUsageError(err) {
			return exitUsage
		}
		return exitFailure
	}

	var ue *usageError
	switch {
	case errors.As(err, &ue):
		fmt.Fprintln(env.stderr, "obscura:", ue.msg)
		return exitUsage

	case errors.Is(err, keystore.ErrNoIdentity):
		env.r.Failure("No identity", "No local identity found. Run 'obscura init' first.")
		return exitFailure

	case errors.Is(err, keystore.ErrExists):
		env.r.Failure("Identity exists", "An identity already exists. Use --force to overwrite it.")
		return exitFailure

	case errors.Is(err, sshclient.ErrNotFound):
		env.r.Failure("Not found", "file not found")
		return exitFailure

	case errors.Is(err, sshclient.ErrTooLarge):
		env.r.Failure("Too large", "file too large")
		return exitFailure

	default:
		var che *changedHostKeyError
		if errors.As(err, &che) {
			env.r.Failure(fmt.Sprintf("Host key CHANGED for %s", che.server),
				fmt.Sprintf("cached:    %s\npresented: %s\nThis may be a man-in-the-middle attack OR a legitimate server key rotation.\nThe connection was refused and the cached key was NOT changed.\nIf this change is expected, run 'obscura known-hosts forget %s' and retry.",
					che.cachedFP, che.presentedFP, che.server))
			return exitFailure
		}
		var re *sshclient.RemoteError
		if errors.As(err, &re) {
			detail := re.Stderr
			if detail == "" {
				detail = "The server rejected the request."
			}
			env.r.Failure("Server error", detail)
			return exitFailure
		}
		env.r.Failure("Failed", err.Error())
		return exitFailure
	}
}

// errorKind maps err to a stable short machine token for --json error output.
func errorKind(err error) string {
	var ue *usageError
	switch {
	case errors.As(err, &ue):
		return "usage"
	case errors.Is(err, keystore.ErrNoIdentity):
		return "no_identity"
	case errors.Is(err, keystore.ErrExists):
		return "identity_exists"
	case errors.Is(err, sshclient.ErrNotFound):
		return "not_found"
	case errors.Is(err, sshclient.ErrTooLarge):
		return "too_large"
	default:
		var re *sshclient.RemoteError
		if errors.As(err, &re) {
			return "server_error"
		}
		var che *changedHostKeyError
		if errors.As(err, &che) {
			return "host_key_changed"
		}
		return "error"
	}
}

// errorMessage maps err to a concise, non-revealing message for --json output,
// mirroring the human card details.
func errorMessage(err error) string {
	var ue *usageError
	switch {
	case errors.As(err, &ue):
		return ue.msg
	case errors.Is(err, keystore.ErrNoIdentity):
		return "no local identity found; run 'obscura init' first"
	case errors.Is(err, keystore.ErrExists):
		return "an identity already exists; use --force to overwrite it"
	case errors.Is(err, sshclient.ErrNotFound):
		return "file not found"
	case errors.Is(err, sshclient.ErrTooLarge):
		return "file too large"
	default:
		var re *sshclient.RemoteError
		if errors.As(err, &re) && re.Stderr != "" {
			return re.Stderr
		}
		return err.Error()
	}
}

// isUsageError reports whether err is a usage error (distinct exit code).
func isUsageError(err error) bool {
	var ue *usageError
	return errors.As(err, &ue)
}
