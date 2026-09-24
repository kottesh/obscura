package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	gossh "golang.org/x/crypto/ssh"
)

// sessionOutput captures a session's buffered stdout and stderr. It is used for
// commands whose stdout is small text (file id or a listing); Download uses
// streamSession instead to avoid buffering large binary payloads.
type sessionOutput struct {
	// stdout is the raw stdout bytes (file id or listing text).
	stdout []byte
	// stderr is the raw stderr diagnostics.
	stderr string
}

// runSession opens a session on client, optionally writes body to stdin, runs
// command, and buffers stdout/stderr. It returns the captured output and the
// SSH exit status. A zero exit is success; a non-zero exit is returned via the
// int with no error (the caller maps it to a typed error). A transport-level
// failure (dial already succeeded, but the channel/run failed for a non-exit
// reason) is returned as the error.
//
// stdin is fully written and closed before the command's exit is awaited, so an
// upload body is delivered even for servers that read stdin to EOF before
// responding.
func runSession(ctx context.Context, client *gossh.Client, command string, body io.Reader) (sessionOutput, int, error) {
	var outBuf, errBuf bytes.Buffer
	code, err := execSession(ctx, client, command, body, &outBuf, &errBuf)
	if err != nil {
		return sessionOutput{}, 0, err
	}
	return sessionOutput{stdout: outBuf.Bytes(), stderr: errBuf.String()}, code, nil
}

// streamSession opens a session on client, runs command (empty command is a
// bare request, e.g. download), and copies stdout verbatim to w while buffering
// stderr. It performs NO text processing on stdout so binary content is
// byte-exact (spec 6.2 download binary safety). It returns the exit status and
// stderr text.
func streamSession(ctx context.Context, client *gossh.Client, command string, body io.Reader, w io.Writer) (int, string, error) {
	var errBuf bytes.Buffer
	code, err := execSession(ctx, client, command, body, w, &errBuf)
	if err != nil {
		return 0, "", err
	}
	return code, errBuf.String(), nil
}

// execSession is the shared session driver. It wires stdin/stdout/stderr, runs
// the command (or a bare shell request when command is empty), and translates
// the result into an exit code. A *gossh.ExitError yields its exit status with
// no error; a *gossh.ExitMissingError (server closed without an exit status) is
// a transport failure. It also honors ctx cancellation by closing the session.
func execSession(ctx context.Context, client *gossh.Client, command string, body io.Reader, stdout, stderr io.Writer) (int, error) {
	sess, err := client.NewSession()
	if err != nil {
		return 0, fmt.Errorf("sshclient: open session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	sess.Stdout = stdout
	sess.Stderr = stderr
	if body != nil {
		sess.Stdin = body
	}

	// Close the session if the context is canceled while the command runs so a
	// hung server cannot block the caller past its deadline. The done channel
	// stops the watcher once the command returns.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()

	// Run sends an "exec" request with the command string. A download uses an
	// empty command, matching how the Obscura server dispatches an f:<id>
	// session with no remote operation to a streaming download (spec 6.2). The
	// server middleware runs on session start regardless, so an empty exec is
	// the correct bare request (the server test drives download the same way).
	runErr := sess.Run(command)

	if runErr == nil {
		return exitOK, nil
	}

	// Prefer a context error so a canceled/timed-out call surfaces that rather
	// than the incidental "session closed" transport error.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}

	var exitErr *gossh.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	var missing *gossh.ExitMissingError
	if errors.As(runErr, &missing) {
		return 0, fmt.Errorf("sshclient: server closed session without exit status: %w", runErr)
	}
	return 0, fmt.Errorf("sshclient: run session: %w", runErr)
}
