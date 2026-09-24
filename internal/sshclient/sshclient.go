// Package sshclient is a thin in-process SSH client that speaks the Obscura
// raw SSH protocol (spec 6.2 commands, 7 CLI-to-SSH mappings). It is what the
// obscura CLI uses under the hood for send/list/receive/delete: it opens SSH
// sessions to an obscurad server, runs the remote command surface the server
// dispatches on, and maps the SSH exit status back into typed Go errors.
//
// The client never shells out to the ssh binary; it uses
// golang.org/x/crypto/ssh directly so it is fully testable against
// internal/sshsrv in-process. It performs no client-side encryption: callers
// are responsible for encrypting before Upload and decrypting after Download
// (spec 6.1). Download copies the server's stdout verbatim with no text
// processing so encrypted bytes round-trip exactly.
package sshclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kottesh/obscura/internal/storage"
	gossh "golang.org/x/crypto/ssh"
)

// Server-side exit codes (must match internal/sshsrv/result.go and spec 6.3).
// The client branches on these to build typed errors; every non-zero code is a
// failure with a concise, server-sanitized stderr message.
const (
	exitOK       = 0
	exitFailure  = 1
	exitInvalid  = 2
	exitNotFound = 3
	exitTooLarge = 4
	exitStorage  = 5
)

// ErrNotFound reports a missing or unauthorized file (spec 6.3). The server
// returns an identical result for "does not exist" and "exists but caller is
// not owner/receiver", so the CLI must not distinguish them.
var ErrNotFound = errors.New("sshclient: file not found")

// ErrTooLarge reports that an upload exceeded the server's size limit (spec
// 6.3).
var ErrTooLarge = errors.New("sshclient: file too large")

// RemoteError is a generic remote failure carrying the server's stderr text
// (already sanitized server-side) and the SSH exit status. It is returned for
// invalid-arguments, storage, and any other non-zero exit that is not mapped
// to a more specific typed error.
type RemoteError struct {
	// ExitCode is the SSH exit status the server reported.
	ExitCode int
	// Stderr is the server's diagnostic text, trimmed of trailing newline.
	Stderr string
}

// Error implements error.
func (e *RemoteError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("sshclient: remote error (exit %d)", e.ExitCode)
	}
	return fmt.Sprintf("sshclient: remote error (exit %d): %s", e.ExitCode, e.Stderr)
}

// Client dials an obscurad server and runs the raw SSH operations. It holds no
// open connection; every method opens a short-lived connection so operations
// can use different SSH usernames (upload/list use the default; download and
// delete use the f:<file_id> routing username) without interfering.
type Client struct {
	// addr is the server host:port.
	addr string
	// signer wraps the caller's Ed25519 signing key for public-key auth.
	signer gossh.Signer
	// hostKeyCallback verifies the server host key (spec 6.1). Callers should
	// pin the expected host key (e.g. gossh.FixedHostKey); InsecureIgnoreHostKey
	// is only for tests.
	hostKeyCallback gossh.HostKeyCallback
	// timeout bounds each dial. Zero means the x/crypto/ssh default (no dial
	// timeout beyond the OS).
	timeout time.Duration
}

// New builds a Client for addr ("host:port") authenticating with the caller's
// Ed25519 signing private key (identity.Identity.SignPriv) and verifying the
// server host key with hostKeyCallback.
//
// hostKeyCallback must not be nil. Production callers should pin the server's
// host key with gossh.FixedHostKey(expectedHostPublicKey) (a known-hosts-style
// pin). gossh.InsecureIgnoreHostKey is only acceptable in tests, because it
// disables host authentication and exposes the session to man-in-the-middle
// attacks.
func New(addr string, signKey ed25519.PrivateKey, hostKeyCallback gossh.HostKeyCallback) (*Client, error) {
	if addr == "" {
		return nil, errors.New("sshclient: empty server address")
	}
	if len(signKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sshclient: signing key must be %d bytes, got %d", ed25519.PrivateKeySize, len(signKey))
	}
	if hostKeyCallback == nil {
		return nil, errors.New("sshclient: nil host key callback; pin the server host key or use InsecureIgnoreHostKey in tests only")
	}
	signer, err := gossh.NewSignerFromKey(signKey)
	if err != nil {
		return nil, fmt.Errorf("sshclient: build signer: %w", err)
	}
	return &Client{
		addr:            addr,
		signer:          signer,
		hostKeyCallback: hostKeyCallback,
		timeout:         30 * time.Second,
	}, nil
}

// SetDialTimeout overrides the per-dial timeout. A value <= 0 clears it.
func (c *Client) SetDialTimeout(d time.Duration) {
	c.timeout = d
}

// clientConfig builds the SSH client config for the given login username. The
// username selects the server route: "" (or any non-"f:" value) is an upload
// or list request, while "f:<file_id>" routes to download/delete (spec 6.2).
func (c *Client) clientConfig(user string) *gossh.ClientConfig {
	return &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(c.signer)},
		HostKeyCallback: c.hostKeyCallback,
		Timeout:         c.timeout,
	}
}

// dial opens a connection using the given login username. The caller must
// Close the returned client.
func (c *Client) dial(ctx context.Context, user string) (*gossh.Client, error) {
	// x/crypto/ssh has no context-aware Dial; honor a canceled context up
	// front and let the ClientConfig.Timeout bound the actual handshake.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, err := gossh.Dial("tcp", c.addr, c.clientConfig(user))
	if err != nil {
		return nil, fmt.Errorf("sshclient: dial %s: %w", c.addr, err)
	}
	return client, nil
}

// Upload opens a normal session (default username; the server ignores it and
// routes by command), runs "-to <addr> [-name <name>] [-carrier <carrier>]",
// streams the encrypted body to stdin, and returns the server-assigned file id
// from stdout (spec 6.2 upload). carrier may be empty (server defaults to
// package) or "package"/"png"; name may be empty. A non-zero exit is mapped to
// a typed error carrying the server's stderr.
func (c *Client) Upload(ctx context.Context, body io.Reader, toAddress, name, carrier string) (fileID string, err error) {
	if toAddress == "" {
		return "", errors.New("sshclient: upload requires a receiver address")
	}
	if carrier != "" && !storage.CarrierType(carrier).Valid() {
		return "", fmt.Errorf("sshclient: invalid carrier %q", carrier)
	}

	cmd := buildUploadCommand(toAddress, name, carrier)

	client, err := c.dial(ctx, "")
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	out, code, runErr := runSession(ctx, client, cmd, body)
	if runErr != nil {
		return "", runErr
	}
	if code != exitOK {
		return "", mapExit(code, out.stderr)
	}
	return strings.TrimSpace(string(out.stdout)), nil
}

// List runs "list [-sent|-received]" and parses each stdout row into a ListRow
// (spec 6.2 list). filter must be "", "sent", or "received"; anything else is
// rejected locally before dialing.
func (c *Client) List(ctx context.Context, filter string) ([]ListRow, error) {
	cmd, err := buildListCommand(filter)
	if err != nil {
		return nil, err
	}

	client, err := c.dial(ctx, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	out, code, runErr := runSession(ctx, client, cmd, nil)
	if runErr != nil {
		return nil, runErr
	}
	if code != exitOK {
		return nil, mapExit(code, out.stderr)
	}
	return ParseListing(out.stdout)
}

// Download connects with username "f:<fileID>" and no remote command, then
// copies the raw encrypted bytes from stdout to w verbatim (spec 6.2 download).
// A missing or unauthorized id returns ErrNotFound. No text processing is done
// on the stream so the bytes are byte-identical to what was uploaded.
func (c *Client) Download(ctx context.Context, fileID string, w io.Writer) error {
	if fileID == "" {
		return ErrNotFound
	}

	client, err := c.dial(ctx, fileRouteUser(fileID))
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	code, stderr, runErr := streamSession(ctx, client, "", nil, w)
	if runErr != nil {
		return runErr
	}
	if code != exitOK {
		return mapExit(code, stderr)
	}
	return nil
}

// Delete connects with username "f:<fileID>" and runs "rm", deleting an owned
// record (spec 6.2 delete). A missing id, or a non-owner caller, returns
// ErrNotFound (the server folds unauthorized into not-found).
func (c *Client) Delete(ctx context.Context, fileID string) error {
	if fileID == "" {
		return ErrNotFound
	}

	client, err := c.dial(ctx, fileRouteUser(fileID))
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	out, code, runErr := runSession(ctx, client, "rm", nil)
	if runErr != nil {
		return runErr
	}
	if code != exitOK {
		return mapExit(code, out.stderr)
	}
	return nil
}

// fileRouteUser builds the "f:<file_id>" login username that routes a session
// to file handling on the server (spec 6.1 reserved prefix).
func fileRouteUser(fileID string) string {
	return "f:" + fileID
}

// buildUploadCommand assembles the upload flag string. The server splits the
// remote command with shell-style tokenization, so values are passed as
// separate tokens; the address, name, and carrier are Obscura-controlled and
// contain no whitespace (the server rejects names with control characters).
func buildUploadCommand(toAddress, name, carrier string) string {
	parts := []string{"-to", toAddress}
	if name != "" {
		parts = append(parts, "-name", name)
	}
	if carrier != "" {
		parts = append(parts, "-carrier", carrier)
	}
	return strings.Join(parts, " ")
}

// buildListCommand assembles the list command for the given filter. Empty is
// the default (both directions); "sent" and "received" map to the -sent and
// -received flags (spec 6.2 list).
func buildListCommand(filter string) (string, error) {
	switch filter {
	case "":
		return "list", nil
	case "sent":
		return "list -sent", nil
	case "received":
		return "list -received", nil
	default:
		return "", fmt.Errorf("sshclient: invalid list filter %q (want \"\", \"sent\", or \"received\")", filter)
	}
}

// mapExit converts a non-zero SSH exit status plus the server's stderr into a
// typed error (spec 6.3). exitNotFound maps to ErrNotFound, exitTooLarge to
// ErrTooLarge, and everything else to a RemoteError carrying the stderr text.
func mapExit(code int, stderr string) error {
	stderr = strings.TrimRight(stderr, "\r\n")
	switch code {
	case exitNotFound:
		return ErrNotFound
	case exitTooLarge:
		return ErrTooLarge
	default:
		return &RemoteError{ExitCode: code, Stderr: stderr}
	}
}
