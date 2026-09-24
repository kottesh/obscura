package sshsrv

import (
	"crypto"
	"crypto/ed25519"
	"errors"

	"github.com/charmbracelet/ssh"
	"github.com/kottesh/obscura/internal/identity"
)

// errNotEd25519 is returned when an authenticated public key is not a raw
// Ed25519 key. Identity is derived only from Ed25519 signing keys (spec 6.1).
var errNotEd25519 = errors.New("sshsrv: public key is not ed25519")

// cryptoPublicKey mirrors golang.org/x/crypto/ssh.CryptoPublicKey: SSH public
// keys backed by a standard-library key expose the underlying crypto.PublicKey.
// For an "ssh-ed25519" key this returns the raw 32-byte ed25519.PublicKey, not
// its wire/authorized_keys encoding.
type cryptoPublicKey interface {
	CryptoPublicKey() crypto.PublicKey
}

// callerUserID derives the authenticated caller's user id from the SSH public
// key used to authenticate. It extracts the RAW ed25519 public key via
// CryptoPublicKey() and hashes THAT with identity.UserIDFromSignPub. It never
// hashes the SSH wire encoding (Marshal/authorized_keys text), which would
// produce a different, spec-incompatible id.
//
// Non-Ed25519 keys are rejected. This is the single point that turns an
// authenticated SSH key into the owner/caller identity used for authorization.
func callerUserID(pub ssh.PublicKey) ([32]byte, error) {
	var zero [32]byte
	if pub == nil {
		return zero, errNotEd25519
	}
	if pub.Type() != "ssh-ed25519" {
		return zero, errNotEd25519
	}
	cpk, ok := pub.(cryptoPublicKey)
	if !ok {
		return zero, errNotEd25519
	}
	raw, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok || len(raw) != ed25519.PublicKeySize {
		return zero, errNotEd25519
	}
	return identity.UserIDFromSignPub(raw), nil
}
