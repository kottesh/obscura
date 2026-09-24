# Obscura

Private SSH file sharing with encrypted PNG carriers.

Obscura is a Go file-sharing system where a sender encrypts any file locally for a
specific receiver, uploads the encrypted result over SSH, and receives a file id.
The receiver lists and downloads that file over SSH and decrypts it locally. The
server only ever stores ciphertext.

- SSH public-key authentication (Ed25519); identity is the authenticated key.
- One recovery seed derives an Ed25519 SSH key and an X25519 encryption key.
- Receiver-specific encryption: ephemeral X25519 + HKDF-SHA-256 + XChaCha20-Poly1305.
- Zstandard compression and BLAKE3 integrity.
- Optional generated-PNG carrier via RGB LSB matching.
- One encrypted `FileRecord` per upload, stored in SQLite.

See [`../docs/system-spec.md`](../docs/system-spec.md) for the full specification.

## Layout

```text
cmd/obscura    user-facing CLI (local crypto, PNG, SSH client wrapper)
cmd/obscurad   SSH server daemon
internal/...    crypto, package format, PNG, storage, SSH routing, CLI rendering
```

## Requirements

- Go 1.24+ (uses standard-library `crypto/ecdh` and `crypto/hkdf`).

## Status

Under active development. Features are built and committed incrementally.
