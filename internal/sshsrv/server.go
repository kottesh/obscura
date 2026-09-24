// Package sshsrv implements the Obscura SSH transport: an Ed25519-only,
// shell-less server that routes each authenticated session to upload, list,
// download, or delete over a locked-down SSH surface (spec section 6).
//
// The server derives the caller identity only from the authenticated SSH
// public key (never a client-supplied value), enforces owner/receiver
// authorization in the storage layer, and returns an identical not-found
// result for missing and unauthorized ids. Raw encrypted bytes go only to the
// session stdout; diagnostics go only to stderr; every request ends with an
// explicit exit code.
package sshsrv

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/kottesh/obscura/internal/storage"
)

// Config configures a Server. Store is required.
type Config struct {
	// Addr is the listen address, e.g. ":2222".
	Addr string
	// HostKeyPath is the path to the PEM-encoded Ed25519 host private key.
	HostKeyPath string
	// Store is the backing file store. Required.
	Store storage.FileStore
	// MaxUpload caps a single upload's encrypted size in bytes. When <= 0 it
	// defaults to storage.MaxContentSize.
	MaxUpload int64
	// IdleTimeout bounds per-session idle duration. When <= 0 a default is used.
	IdleTimeout time.Duration
	// MaxTimeout bounds total per-session duration. When <= 0 a default is used.
	MaxTimeout time.Duration
}

// Default per-session limits (spec 6.1 duration limits).
const (
	defaultIdleTimeout = 2 * time.Minute
	defaultMaxTimeout  = 30 * time.Minute
)

// sessionAdapter adapts an ssh.Session to the internal session interface used
// by the handlers. ssh.Session embeds gossh.Channel, which provides Read,
// Write, and Stderr; Exit and the interface's Stderr method come from the
// session directly.
type sessionAdapter struct {
	ssh.Session
}

// Stderr returns the session's stderr stream as an io.Writer, matching the
// internal session interface.
func (a sessionAdapter) Stderr() io.Writer {
	return a.Session.Stderr()
}

// NewServer builds a locked-down wish/ssh server from cfg: Ed25519-only public
// key auth, no PTY, no shell/forwarding handlers, and idle/max timeouts. The
// only registered handler routes the session to the file operations.
func NewServer(cfg Config) (*ssh.Server, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("sshsrv: nil store")
	}
	maxUpload := cfg.MaxUpload
	if maxUpload <= 0 {
		maxUpload = storage.MaxContentSize
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	maxT := cfg.MaxTimeout
	if maxT <= 0 {
		maxT = defaultMaxTimeout
	}

	handler := func(s ssh.Session) {
		serve(s, cfg.Store, maxUpload)
	}

	opts := []ssh.Option{
		wish.WithAddress(cfg.Addr),
		wish.WithIdleTimeout(idle),
		wish.WithMaxTimeout(maxT),
		// Ed25519-only public-key auth; password auth is never registered, so
		// it is disabled by default.
		wish.WithPublicKeyAuth(publicKeyHandler),
		// Deny PTY allocation; no shell is ever spawned (spec 6.1).
		ssh.NoPty(),
		wish.WithMiddleware(func(next ssh.Handler) ssh.Handler {
			// Single terminal middleware: run our handler, then close. No
			// shell, no forwarding, no line-buffering middleware in front of
			// stdout.
			return handler
		}),
	}
	// Load a host key from a path when one is configured. Otherwise provide an
	// in-memory ephemeral Ed25519 host key so wish.NewServer sees a host signer
	// and does NOT auto-generate id_ed25519 in the current working directory
	// (its default when no host key is set). Callers may still override the
	// signer via (*ssh.Server).AddHostKey after construction (used in tests).
	if cfg.HostKeyPath != "" {
		opts = append(opts, wish.WithHostKeyPath(cfg.HostKeyPath))
	} else {
		pemKey, err := ephemeralHostKeyPEM()
		if err != nil {
			return nil, err
		}
		opts = append(opts, wish.WithHostKeyPEM(pemKey))
	}

	srv, err := wish.NewServer(opts...)
	if err != nil {
		return nil, fmt.Errorf("sshsrv: build server: %w", err)
	}

	// Explicitly disable forwarding: leave the forwarding callbacks nil (the
	// default denies) and register no channel/request handlers for them.
	srv.LocalPortForwardingCallback = nil
	srv.ReversePortForwardingCallback = nil
	srv.ChannelHandlers = map[string]ssh.ChannelHandler{
		"session": ssh.DefaultSessionHandler,
	}
	srv.RequestHandlers = map[string]ssh.RequestHandler{}

	return srv, nil
}

// ephemeralHostKeyPEM generates a fresh in-memory Ed25519 host key encoded as
// PKCS#8 PEM. It is used only to prevent wish.NewServer from writing a default
// id_ed25519 file to the working directory when no persistent host key path is
// configured; production deployments should always set Config.HostKeyPath.
func ephemeralHostKeyPEM() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshsrv: generate ephemeral host key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sshsrv: marshal ephemeral host key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// publicKeyHandler accepts only Ed25519 keys whose raw crypto key can be
// extracted (spec 6.1). Returning false rejects every other key type at auth
// time, before any session runs.
func publicKeyHandler(_ ssh.Context, key ssh.PublicKey) bool {
	_, err := callerUserID(key)
	return err == nil
}

// serve derives the caller id from the authenticated key and dispatches the
// session (spec 6.2). It uses the session's context, which is canceled when the
// client connection closes, and ends every path with an explicit exit code and
// never panics or calls os.Exit out of a handler.
func serve(sess ssh.Session, store storage.FileStore, maxUpload int64) {
	s := sessionAdapter{sess}
	ctx := sess.Context()

	caller, err := callerUserID(sess.PublicKey())
	if err != nil {
		// Auth already rejected non-Ed25519 keys; this is defensive.
		_ = exitInvalidResult(s, "unauthorized")
		return
	}

	r, fileID := dispatch(sess.User(), sess.Command())
	switch r {
	case routeFile:
		_ = handleFile(ctx, s, store, caller, fileID, sess.Command())
	case routeList:
		// Drop the leading "list" token before parsing flags.
		_ = handleList(ctx, s, store, caller, sess.Command()[1:])
	default:
		_ = handleUpload(ctx, s, store, caller, sess.Command(), maxUpload)
	}
}
