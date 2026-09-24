// Package keystore implements local persistence of the Obscura user identity
// for the CLI. It stores only the 32-byte master seed on disk; every key is
// re-derived on load via identity.DeriveIdentity (system spec sections 2 and
// 7). It backs 'obscura init [--recover]', 'obscura address', and the identity
// loading used by all other commands.
//
// # Storage layout
//
// The seed is written to <base>/obscura/seed where <base> defaults to
// os.UserConfigDir(). On Linux this is typically ~/.config/obscura/seed, on
// macOS ~/Library/Application Support/obscura/seed, and on Windows
// %AppData%\obscura\seed. Tests and the CLI may override <base> with an
// explicit directory so nothing is written to the real config location.
//
// # Security
//
// The config directory is created with mode 0700 and the seed file with mode
// 0600. The seed is never logged or printed. Writes are atomic: the seed is
// written to a temporary file in the same directory and renamed into place, so
// a crash can never leave a half-written seed. Only the master seed is stored;
// the Ed25519 and X25519 private keys are always re-derived and never touch
// disk here.
package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kottesh/obscura/internal/identity"
	"github.com/mr-tron/base58"
)

// ErrNoIdentity is returned by Load and Address when no seed file exists so the
// CLI can tell the user to run 'obscura init'.
var ErrNoIdentity = errors.New("keystore: no identity found (run 'obscura init')")

// ErrExists is returned by Init and Recover when a seed file already exists and
// force is not set, to avoid clobbering an existing identity.
var ErrExists = errors.New("keystore: identity already exists (use force to overwrite)")

const (
	// appDir is the per-user subdirectory under the config base.
	appDir = "obscura"
	// seedFile is the name of the seed file within appDir.
	seedFile = "seed"

	// dirPerm and filePerm are the mandated permissions for the config
	// directory and the seed file respectively.
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
)

// DefaultDir returns the default config base directory for Obscura, derived
// from os.UserConfigDir. The seed lives at DefaultDir()/obscura/seed. Callers
// (including tests) may pass their own base directory to the other functions
// instead of using this default.
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("keystore: resolve config dir: %w", err)
	}
	return base, nil
}

// seedPath returns the full path to the seed file for a given config base dir.
func seedPath(dir string) string {
	return filepath.Join(dir, appDir, seedFile)
}

// Init creates a fresh identity under the given config base dir. It generates a
// new 32-byte master seed, writes it atomically, and returns the derived
// Identity.
//
// If a seed already exists, Init refuses to overwrite it and returns ErrExists
// unless force is true. Refuse-overwrite is the default so a second init cannot
// silently clobber an existing identity.
func Init(dir string, force bool) (*identity.Identity, error) {
	seed, err := identity.GenerateSeed()
	if err != nil {
		return nil, err
	}
	return writeSeed(dir, seed, force)
}

// Recover writes a provided 32-byte master seed as the identity, for use by
// 'obscura init --recover'. The seed is typically decoded from a backup with
// DecodeSeed. Like Init, it refuses to overwrite an existing seed and returns
// ErrExists unless force is true.
func Recover(dir string, seed []byte, force bool) (*identity.Identity, error) {
	if len(seed) != identity.SeedSize {
		return nil, fmt.Errorf("keystore: recover seed must be %d bytes, got %d", identity.SeedSize, len(seed))
	}
	// Copy so a caller mutating the slice cannot affect what we persist.
	s := make([]byte, identity.SeedSize)
	copy(s, seed)
	return writeSeed(dir, s, force)
}

// writeSeed validates the seed by deriving an identity, then persists it
// atomically, honoring the refuse-overwrite policy.
func writeSeed(dir string, seed []byte, force bool) (*identity.Identity, error) {
	// Derive first so an unusable seed is rejected before touching disk.
	id, err := identity.DeriveIdentity(seed)
	if err != nil {
		return nil, err
	}

	confDir := filepath.Join(dir, appDir)
	if err := os.MkdirAll(confDir, dirPerm); err != nil {
		return nil, fmt.Errorf("keystore: create config dir: %w", err)
	}
	// MkdirAll respects umask, so enforce 0700 explicitly for an existing dir.
	if err := os.Chmod(confDir, dirPerm); err != nil {
		return nil, fmt.Errorf("keystore: set config dir permissions: %w", err)
	}

	path := seedPath(dir)
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil, ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("keystore: stat seed: %w", err)
		}
	}

	if err := atomicWrite(confDir, path, seed); err != nil {
		return nil, err
	}
	return id, nil
}

// atomicWrite writes data to path via a temp file in the same directory
// followed by rename. The temp file is created with filePerm and removed on any
// failure so no partial or stray file is left behind.
func atomicWrite(confDir, path string, data []byte) error {
	tmp, err := os.CreateTemp(confDir, "seed-*.tmp")
	if err != nil {
		return fmt.Errorf("keystore: create temp seed: %w", err)
	}
	tmpName := tmp.Name()

	// Ensure cleanup if anything below fails before a successful rename.
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(filePerm); err != nil {
		return fmt.Errorf("keystore: set temp seed permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("keystore: write seed: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("keystore: sync seed: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keystore: close seed: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("keystore: commit seed: %w", err)
	}
	committed = true
	return nil
}

// Load reads the seed file under the given config base dir, re-derives, and
// returns the Identity. It returns ErrNoIdentity if no seed exists.
func Load(dir string) (*identity.Identity, error) {
	path := seedPath(dir)
	seed, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoIdentity
		}
		return nil, fmt.Errorf("keystore: read seed: %w", err)
	}
	if len(seed) != identity.SeedSize {
		return nil, fmt.Errorf("keystore: corrupt seed: got %d bytes, expected %d", len(seed), identity.SeedSize)
	}
	id, err := identity.DeriveIdentity(seed)
	if err != nil {
		return nil, err
	}
	return id, nil
}

// Address loads the identity under the given config base dir and returns its
// public address, base58(sign_pk || box_pk). It returns ErrNoIdentity if no
// seed exists.
func Address(dir string) (string, error) {
	id, err := Load(dir)
	if err != nil {
		return "", err
	}
	return id.Address()
}

// EncodeSeed encodes a 32-byte master seed as a Base58 string suitable for a
// copy-pasteable backup phrase. Base58 is used for consistency with the public
// address encoding and avoids ambiguous characters. This is what the CLI can
// display once at init for backup and what 'obscura init --recover' consumes.
func EncodeSeed(seed []byte) string {
	return base58.Encode(seed)
}

// DecodeSeed decodes a Base58 backup string into a 32-byte master seed. It
// rejects invalid Base58 and any decoded length other than SeedSize.
func DecodeSeed(s string) ([]byte, error) {
	raw, err := base58.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode seed: invalid base58: %w", err)
	}
	if len(raw) != identity.SeedSize {
		return nil, fmt.Errorf("keystore: decode seed: got %d bytes, expected %d", len(raw), identity.SeedSize)
	}
	return raw, nil
}
