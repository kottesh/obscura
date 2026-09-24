// Package identity implements the Obscura identity layer: a single 32-byte
// master seed from which independent Ed25519 signing and X25519 encryption
// keys are derived, plus the user id and public address described in the
// system specification (section 2).
package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"
	"github.com/zeebo/blake3"
)

// SeedSize is the length in bytes of the master seed.
const SeedSize = 32

// HKDF info labels for domain separation between the signing and encryption
// key derivations. These labels are part of the on-disk/on-wire contract and
// must not change without a version bump.
const (
	signInfo = "obscura/identity/v1"
	boxInfo  = "obscura/encryption/v1"
)

// addressLen is the decoded length of a public address: sign_pk (32) || box_pk (32).
const addressLen = ed25519.PublicKeySize + 32

// Identity holds a user's master seed and all derived key material. The seed
// and private keys are secret and must never be logged, printed, or sent to
// the server.
type Identity struct {
	// Seed is the 32-byte master seed.
	Seed []byte

	// SignPriv is the Ed25519 private key used only for SSH identity.
	SignPriv ed25519.PrivateKey
	// SignPub is the Ed25519 public key.
	SignPub ed25519.PublicKey

	// BoxPriv is the X25519 private key used only for file encryption.
	BoxPriv *ecdh.PrivateKey
	// BoxPub is the X25519 public key.
	BoxPub *ecdh.PublicKey
}

// GenerateSeed returns a fresh 32-byte master seed from crypto/rand.
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("identity: generate seed: %w", err)
	}
	return seed, nil
}

// NewIdentity generates a fresh master seed and derives the identity from it.
func NewIdentity() (*Identity, error) {
	seed, err := GenerateSeed()
	if err != nil {
		return nil, err
	}
	return DeriveIdentity(seed)
}

// DeriveIdentity deterministically derives the Ed25519 and X25519 keys from a
// 32-byte master seed. The seed must be exactly SeedSize bytes.
func DeriveIdentity(seed []byte) (*Identity, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("identity: seed must be %d bytes, got %d", SeedSize, len(seed))
	}

	// Derive independent signing and encryption seeds via HKDF-SHA-256 with
	// distinct info labels for domain separation. salt is nil per the spec.
	signSeed, err := hkdf.Key(sha256.New, seed, nil, signInfo, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("identity: derive sign seed: %w", err)
	}
	boxSeed, err := hkdf.Key(sha256.New, seed, nil, boxInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("identity: derive box seed: %w", err)
	}

	signPriv := ed25519.NewKeyFromSeed(signSeed)
	signPub, ok := signPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("identity: unexpected ed25519 public key type")
	}

	// NewPrivateKey requires a 32-byte input and stores it as the X25519
	// scalar; crypto/ecdh applies RFC 7748 clamping at ECDH/PublicKey time,
	// not on the stored bytes.
	boxPriv, err := ecdh.X25519().NewPrivateKey(boxSeed)
	if err != nil {
		return nil, fmt.Errorf("identity: derive x25519 key: %w", err)
	}

	// Copy the seed so callers cannot mutate our stored copy and vice versa.
	seedCopy := make([]byte, SeedSize)
	copy(seedCopy, seed)

	return &Identity{
		Seed:     seedCopy,
		SignPriv: signPriv,
		SignPub:  signPub,
		BoxPriv:  boxPriv,
		BoxPub:   boxPriv.PublicKey(),
	}, nil
}

// UserID returns the user id, BLAKE3(sign_pk), as a 32-byte array.
func (id *Identity) UserID() [32]byte {
	return UserIDFromSignPub(id.SignPub)
}

// UserIDFromSignPub computes user_id = BLAKE3(sign_pk).
func UserIDFromSignPub(pub ed25519.PublicKey) [32]byte {
	return blake3.Sum256(pub)
}

// Address returns the public address, base58(sign_pk || box_pk).
func (id *Identity) Address() (string, error) {
	raw := make([]byte, 0, addressLen)
	raw = append(raw, id.SignPub...)
	raw = append(raw, id.BoxPub.Bytes()...)
	if len(raw) != addressLen {
		return "", fmt.Errorf("identity: internal address length %d, expected %d", len(raw), addressLen)
	}
	return base58.Encode(raw), nil
}

// Address is a decoded public address containing a receiver's public keys and
// derived user id. It carries no secret material.
type Address struct {
	// SignPub is the receiver's Ed25519 public key (32 bytes).
	SignPub ed25519.PublicKey
	// BoxPub is the receiver's X25519 public key.
	BoxPub *ecdh.PublicKey
	// UserID is BLAKE3(SignPub).
	UserID [32]byte
}

// DecodeAddress decodes a base58 public address into its component keys. It
// rejects invalid Base58 data and any decoded length other than 64 bytes.
func DecodeAddress(addr string) (*Address, error) {
	raw, err := base58.Decode(addr)
	if err != nil {
		return nil, fmt.Errorf("identity: decode address: invalid base58: %w", err)
	}
	if len(raw) != addressLen {
		return nil, fmt.Errorf("identity: decode address: got %d bytes, expected %d", len(raw), addressLen)
	}

	signPub := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	copy(signPub, raw[:ed25519.PublicKeySize])

	boxPub, err := ecdh.X25519().NewPublicKey(raw[ed25519.PublicKeySize:])
	if err != nil {
		return nil, fmt.Errorf("identity: decode address: invalid x25519 key: %w", err)
	}

	return &Address{
		SignPub: signPub,
		BoxPub:  boxPub,
		UserID:  UserIDFromSignPub(signPub),
	}, nil
}
