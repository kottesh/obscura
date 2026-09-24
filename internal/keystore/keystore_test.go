package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kottesh/obscura/internal/identity"
)

// fixedSeed returns a deterministic 32-byte seed (0x00..0x1f).
func fixedSeed() []byte {
	seed := make([]byte, identity.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func TestInitFresh(t *testing.T) {
	dir := t.TempDir()

	id, err := Init(dir, false)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if id == nil {
		t.Fatal("Init returned nil identity")
	}

	// Seed file exists with mode 0600.
	fi, err := os.Stat(seedPath(dir))
	if err != nil {
		t.Fatalf("stat seed: %v", err)
	}
	if got := fi.Mode().Perm(); got != filePerm {
		t.Fatalf("seed file mode = %o, want %o", got, filePerm)
	}
	if fi.Size() != int64(identity.SeedSize) {
		t.Fatalf("seed file size = %d, want %d", fi.Size(), identity.SeedSize)
	}

	// Config dir exists with mode 0700.
	di, err := os.Stat(filepath.Join(dir, appDir))
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if got := di.Mode().Perm(); got != dirPerm {
		t.Fatalf("config dir mode = %o, want %o", got, dirPerm)
	}

	// The returned identity must be derivable and stable through Load.
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	gotAddr, err := loaded.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	wantAddr, err := id.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if gotAddr != wantAddr {
		t.Fatalf("loaded address = %q, want %q", gotAddr, wantAddr)
	}
}

func TestInitRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()

	first, err := Init(dir, false)
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}
	firstAddr, err := first.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	before, err := os.ReadFile(seedPath(dir))
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}

	// Second init without force must fail and leave the seed untouched.
	if _, err := Init(dir, false); !errors.Is(err, ErrExists) {
		t.Fatalf("second Init err = %v, want ErrExists", err)
	}
	after, err := os.ReadFile(seedPath(dir))
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("second Init modified the existing seed")
	}
	stillAddr, err := Address(dir)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if stillAddr != firstAddr {
		t.Fatalf("address changed after refused init: got %q, want %q", stillAddr, firstAddr)
	}
}

func TestInitForceOverwrites(t *testing.T) {
	dir := t.TempDir()

	first, err := Init(dir, false)
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}
	firstAddr, err := first.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	second, err := Init(dir, true)
	if err != nil {
		t.Fatalf("force Init: %v", err)
	}
	secondAddr, err := second.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if firstAddr == secondAddr {
		t.Fatal("force Init produced the same identity as before (expected a new seed)")
	}
}

func TestRecoverRoundTrip(t *testing.T) {
	dir := t.TempDir()
	seed := fixedSeed()

	id, err := Recover(dir, seed, false)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	want, err := identity.DeriveIdentity(seed)
	if err != nil {
		t.Fatalf("DeriveIdentity: %v", err)
	}
	wantAddr, err := want.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	recAddr, err := id.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if recAddr != wantAddr {
		t.Fatalf("recovered address = %q, want %q", recAddr, wantAddr)
	}

	// Load must round-trip to the same address.
	loadedAddr, err := Address(dir)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if loadedAddr != wantAddr {
		t.Fatalf("loaded address = %q, want %q", loadedAddr, wantAddr)
	}

	// The on-disk bytes must equal the recovered seed.
	onDisk, err := os.ReadFile(seedPath(dir))
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	if string(onDisk) != string(seed) {
		t.Fatal("on-disk seed differs from the recovered seed")
	}
}

func TestRecoverRejectsBadLength(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		seed []byte
	}{
		{"empty", nil},
		{"short", make([]byte, identity.SeedSize-1)},
		{"long", make([]byte, identity.SeedSize+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Recover(dir, tc.seed, false); err == nil {
				t.Fatal("Recover accepted a wrong-length seed")
			}
			if _, err := os.Stat(seedPath(dir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Recover wrote a seed on failure: stat err = %v", err)
			}
		})
	}
}

func TestRecoverRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, err := Recover(dir, fixedSeed(), false); err != nil {
		t.Fatalf("first Recover: %v", err)
	}
	other := make([]byte, identity.SeedSize)
	for i := range other {
		other[i] = 0xff
	}
	if _, err := Recover(dir, other, false); !errors.Is(err, ErrExists) {
		t.Fatalf("second Recover err = %v, want ErrExists", err)
	}
	onDisk, err := os.ReadFile(seedPath(dir))
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	if string(onDisk) != string(fixedSeed()) {
		t.Fatal("refused Recover modified the existing seed")
	}
}

func TestLoadNoIdentity(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Load err = %v, want ErrNoIdentity", err)
	}
	if _, err := Address(dir); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Address err = %v, want ErrNoIdentity", err)
	}
}

func TestLoadRejectsCorruptSeed(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, appDir)
	if err := os.MkdirAll(confDir, dirPerm); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(seedPath(dir), []byte("too short"), filePerm); err != nil {
		t.Fatalf("write corrupt seed: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a corrupt seed")
	} else if errors.Is(err, ErrNoIdentity) {
		t.Fatal("Load reported ErrNoIdentity for a present but corrupt seed")
	}
}

func TestEncodeDecodeSeedRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		seed []byte
	}{
		{"fixed", fixedSeed()},
		{"zeros", make([]byte, identity.SeedSize)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc := EncodeSeed(tc.seed)
			if enc == "" {
				t.Fatal("EncodeSeed returned empty string")
			}
			dec, err := DecodeSeed(enc)
			if err != nil {
				t.Fatalf("DecodeSeed: %v", err)
			}
			if string(dec) != string(tc.seed) {
				t.Fatalf("round-trip mismatch: got %x, want %x", dec, tc.seed)
			}
		})
	}

	// A freshly generated seed also round-trips.
	seed, err := identity.GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}
	dec, err := DecodeSeed(EncodeSeed(seed))
	if err != nil {
		t.Fatalf("DecodeSeed: %v", err)
	}
	if string(dec) != string(seed) {
		t.Fatal("generated seed did not round-trip")
	}
}

func TestDecodeSeedRejects(t *testing.T) {
	// Base58 of a 31-byte and a 33-byte value.
	short := EncodeSeed(make([]byte, identity.SeedSize-1))
	long := EncodeSeed(make([]byte, identity.SeedSize+1))

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"invalid base58 char", "0OIl+/"},
		{"wrong length short", short},
		{"wrong length long", long},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeSeed(tc.in); err == nil {
				t.Fatalf("DecodeSeed(%q) succeeded, want error", tc.in)
			}
		})
	}
}

func TestAtomicWriteLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, false); err != nil {
		t.Fatalf("Init: %v", err)
	}
	confDir := filepath.Join(dir, appDir)
	entries, err := os.ReadDir(confDir)
	if err != nil {
		t.Fatalf("read config dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != seedFile {
			t.Fatalf("unexpected file left in config dir: %q", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %q", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("config dir has %d entries, want 1", len(entries))
	}
}

func TestDefaultDir(t *testing.T) {
	got, err := DefaultDir()
	if err != nil {
		t.Fatalf("DefaultDir: %v", err)
	}
	if got == "" {
		t.Fatal("DefaultDir returned empty path")
	}
}
