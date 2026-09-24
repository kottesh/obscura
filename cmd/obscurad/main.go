// Command obscurad runs the Obscura SSH server (spec section 6). It loads or
// generates an Ed25519 host key, opens the SQLite file store, and serves the
// locked-down SSH transport that routes uploads, listings, downloads, and
// deletes.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kottesh/obscura/internal/sshsrv"
	"github.com/kottesh/obscura/internal/storage"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "obscurad:", err)
		os.Exit(1)
	}
}

// config holds parsed command-line flags.
type config struct {
	addr        string
	hostKeyPath string
	dbPath      string
}

// parseFlags parses obscurad's command-line flags. It is split out so it can be
// unit-tested without starting the server.
func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("obscurad", flag.ContinueOnError)
	var cfg config
	fs.StringVar(&cfg.addr, "addr", ":2222", "listen address")
	fs.StringVar(&cfg.hostKeyPath, "host-key", "obscura_host_ed25519", "path to the Ed25519 host key (PEM); generated if missing")
	fs.StringVar(&cfg.dbPath, "db", "obscura.db", "path to the SQLite database")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return cfg, nil
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	if err := ensureHostKey(cfg.hostKeyPath); err != nil {
		return err
	}

	ctx := context.Background()
	store, err := storage.Open(ctx, cfg.dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	srv, err := sshsrv.NewServer(sshsrv.Config{
		Addr:        cfg.addr,
		HostKeyPath: cfg.hostKeyPath,
		Store:       store,
	})
	if err != nil {
		return err
	}

	log.Printf("obscurad listening on %s (db=%s host-key=%s)", cfg.addr, cfg.dbPath, cfg.hostKeyPath)
	if err := srv.ListenAndServe(); err != nil {
		return err
	}
	return nil
}

// ensureHostKey loads the Ed25519 host key at path, generating and persisting a
// fresh one (PEM, 0600) if the file does not exist.
func ensureHostKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat host key: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate host key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal host key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create host key dir: %w", err)
		}
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return fmt.Errorf("write host key: %w", err)
	}
	log.Printf("generated new Ed25519 host key at %s", path)
	return nil
}
