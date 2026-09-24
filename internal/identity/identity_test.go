package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/mr-tron/base58"
)

// fixedSeed is a deterministic 32-byte seed (0x00..0x1f) used for golden vectors.
func fixedSeed() []byte {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// Golden vectors locked in from DeriveIdentity(fixedSeed()). Any change here
// signals a break in deterministic derivation compatibility.
const (
	goldenSignPub = "2959dfc770a862b542c9ed4edcc1f813fcc220ea124cc12e4a0436ac9bb0c79f"
	goldenBoxPub  = "082e3b387de678f76dd565a2260426f07508b9a6b06acb493330823644756232"
	goldenUserID  = "6251021abdb986a0bbd82f7a89647b47cff3bfc647799197393e9bcf25e76446"
	goldenAddress = "px9xtPLE7cpqb1TabvE2kkKnex4wFybbLHoCK4W41iVt8yGnV8uchb1xHGRiCcJ6nNxWmdFkyEEkYQCPnLe7RVT"
)

func TestGenerateSeed(t *testing.T) {
	s1, err := GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}
	if len(s1) != SeedSize {
		t.Fatalf("seed length = %d, want %d", len(s1), SeedSize)
	}

	s2, err := GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed: %v", err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("two GenerateSeed calls returned identical seeds")
	}
}

func TestDeriveIdentityGolden(t *testing.T) {
	id, err := DeriveIdentity(fixedSeed())
	if err != nil {
		t.Fatalf("DeriveIdentity: %v", err)
	}

	uid := id.UserID()
	addr, err := id.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"sign_pk", hex.EncodeToString(id.SignPub), goldenSignPub},
		{"box_pk", hex.EncodeToString(id.BoxPub.Bytes()), goldenBoxPub},
		{"user_id", hex.EncodeToString(uid[:]), goldenUserID},
		{"address", addr, goldenAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %s, want %s", tt.name, tt.got, tt.want)
			}
		})
	}

	// UserIDFromSignPub must match the method result.
	if got := UserIDFromSignPub(id.SignPub); got != uid {
		t.Errorf("UserIDFromSignPub mismatch: %x != %x", got, uid)
	}
}

func TestDeriveIdentityDeterministic(t *testing.T) {
	seed := fixedSeed()
	a, err := DeriveIdentity(seed)
	if err != nil {
		t.Fatalf("DeriveIdentity a: %v", err)
	}
	b, err := DeriveIdentity(seed)
	if err != nil {
		t.Fatalf("DeriveIdentity b: %v", err)
	}

	if !a.SignPriv.Equal(b.SignPriv) {
		t.Error("sign private keys differ across derivations")
	}
	if !bytes.Equal(a.SignPub, b.SignPub) {
		t.Error("sign public keys differ across derivations")
	}
	if !a.BoxPriv.Equal(b.BoxPriv) {
		t.Error("box private keys differ across derivations")
	}
	if !bytes.Equal(a.BoxPub.Bytes(), b.BoxPub.Bytes()) {
		t.Error("box public keys differ across derivations")
	}
	if a.UserID() != b.UserID() {
		t.Error("user ids differ across derivations")
	}
}

func TestDeriveIdentitySeedLength(t *testing.T) {
	tests := []struct {
		name string
		seed []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, SeedSize-1)},
		{"too long", make([]byte, SeedSize+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DeriveIdentity(tt.seed); err == nil {
				t.Errorf("DeriveIdentity(%d bytes) = nil error, want error", len(tt.seed))
			}
		})
	}
}

func TestDeriveIdentitySeedCopy(t *testing.T) {
	seed := fixedSeed()
	id, err := DeriveIdentity(seed)
	if err != nil {
		t.Fatalf("DeriveIdentity: %v", err)
	}
	// Mutating the caller's seed must not affect the stored copy.
	seed[0] ^= 0xff
	if id.Seed[0] == seed[0] {
		t.Error("Identity.Seed aliases the caller's seed slice")
	}
}

func TestSignVsBoxSeparation(t *testing.T) {
	// Distinct HKDF info labels must yield distinct signing and encryption
	// material, verified indirectly through the derived public keys.
	id, err := DeriveIdentity(fixedSeed())
	if err != nil {
		t.Fatalf("DeriveIdentity: %v", err)
	}
	if bytes.Equal(id.SignPub, id.BoxPub.Bytes()) {
		t.Error("sign_pk and box_pk are identical; HKDF labels not separated")
	}
}

func TestAddressRoundTrip(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	addr, err := id.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	decoded, err := DecodeAddress(addr)
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}

	if !bytes.Equal(decoded.SignPub, id.SignPub) {
		t.Errorf("SignPub mismatch: got %x, want %x", decoded.SignPub, id.SignPub)
	}
	if !bytes.Equal(decoded.BoxPub.Bytes(), id.BoxPub.Bytes()) {
		t.Errorf("BoxPub mismatch: got %x, want %x", decoded.BoxPub.Bytes(), id.BoxPub.Bytes())
	}
	if decoded.UserID != id.UserID() {
		t.Errorf("UserID mismatch: got %x, want %x", decoded.UserID, id.UserID())
	}
}

func TestDecodeAddressGolden(t *testing.T) {
	decoded, err := DecodeAddress(goldenAddress)
	if err != nil {
		t.Fatalf("DecodeAddress: %v", err)
	}
	if got := hex.EncodeToString(decoded.SignPub); got != goldenSignPub {
		t.Errorf("SignPub = %s, want %s", got, goldenSignPub)
	}
	if got := hex.EncodeToString(decoded.BoxPub.Bytes()); got != goldenBoxPub {
		t.Errorf("BoxPub = %s, want %s", got, goldenBoxPub)
	}
	if got := hex.EncodeToString(decoded.UserID[:]); got != goldenUserID {
		t.Errorf("UserID = %s, want %s", got, goldenUserID)
	}
}

func TestDecodeAddressErrors(t *testing.T) {
	// Build a valid 64-byte address to derive too-short / too-long variants.
	id, err := DeriveIdentity(fixedSeed())
	if err != nil {
		t.Fatalf("DeriveIdentity: %v", err)
	}
	valid, err := id.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	// Encode 32- and 96-byte payloads for wrong-length rejection.
	shortAddr := encodeRaw(t, 32)
	longAddr := encodeRaw(t, 96)

	tests := []struct {
		name string
		addr string
	}{
		{"malformed base58 (0)", "0OIl"},         // 0, O, I, l are not in the base58 alphabet
		{"malformed base58 (non-alpha)", "!!!!"}, // invalid characters
		{"empty string", ""},                     // decodes to 0 bytes
		{"too short (32 bytes)", shortAddr},
		{"too long (96 bytes)", longAddr},
		{"truncated valid", valid[:len(valid)-4]}, // corrupts length/content
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeAddress(tt.addr); err == nil {
				t.Errorf("DecodeAddress(%q) = nil error, want error", tt.addr)
			}
		})
	}

	// Sanity: the valid address must still decode.
	if _, err := DecodeAddress(valid); err != nil {
		t.Errorf("valid address failed to decode: %v", err)
	}
}

func TestNewIdentityDistinct(t *testing.T) {
	a, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity a: %v", err)
	}
	b, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity b: %v", err)
	}
	if bytes.Equal(a.SignPub, b.SignPub) {
		t.Error("two NewIdentity calls produced identical sign_pk")
	}
	if a.UserID() == b.UserID() {
		t.Error("two NewIdentity calls produced identical user_id")
	}
}

func TestUserIDFromSignPub(t *testing.T) {
	signPub, err := hex.DecodeString(goldenSignPub)
	if err != nil {
		t.Fatalf("decode golden sign_pub: %v", err)
	}
	uid := UserIDFromSignPub(ed25519.PublicKey(signPub))
	if got := hex.EncodeToString(uid[:]); got != goldenUserID {
		t.Errorf("UserIDFromSignPub = %s, want %s", got, goldenUserID)
	}
}

// encodeRaw base58-encodes n deterministic bytes for wrong-length tests,
// using the same encoder the package uses.
func encodeRaw(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return base58.Encode(raw)
}
