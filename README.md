# Obscura

Private SSH file sharing with encrypted PNG carriers.

Obscura is a Go file-sharing system. A sender encrypts any file locally for a
specific receiver, uploads the encrypted result over SSH, and receives a file id.
The receiver lists and downloads that file over SSH and decrypts it locally. The
server only ever stores ciphertext — it never sees plaintext, content keys, or any
receiver private key.

- SSH public-key authentication (Ed25519); identity is the authenticated key.
- One recovery seed derives an Ed25519 SSH key and an X25519 encryption key.
- Receiver-specific encryption: ephemeral X25519 + HKDF-SHA-256 + XChaCha20-Poly1305.
- Zstandard compression and BLAKE3 integrity.
- Optional generated-PNG carrier via RGB LSB matching.
- One encrypted `FileRecord` per upload, stored in SQLite.

See [`../docs/system-spec.md`](../docs/system-spec.md) for the full specification.

## Requirements

- Go 1.26+ (uses standard-library `crypto/ecdh` and `crypto/hkdf`; the maintained
  SQLite and `x/crypto`/`x/sys` dependencies set the 1.26 floor).
- [`just`](https://github.com/casey/just) (optional) for the task runner below.

## Layout

```text
cmd/obscura     user-facing CLI (local crypto, PNG, SSH client wrapper)
cmd/obscurad    SSH server daemon
internal/identity   seed-derived Ed25519/X25519 identity, user id, address
internal/pkgfmt     receiver-encrypted file package (OBSC format)
internal/carrier    optional PNG LSB-matching steganography carrier
internal/storage    SQLite FileStore with authorized access
internal/sshsrv     locked-down Ed25519 SSH server and routing
internal/sshclient  in-process SSH client for the raw protocol
internal/keystore   local identity persistence
internal/ui         Lip Gloss terminal renderer with strict stream discipline
```

## Build

```sh
just build          # build ./bin/obscura and ./bin/obscurad
# or, without just:
go build -o bin/obscura  ./cmd/obscura
go build -o bin/obscurad ./cmd/obscurad
```

## Quickstart

The example below runs the server and two identities (a sender and a receiver) on
one machine. In practice each user runs `obscura` on their own machine against a
shared `obscurad`.

### 1. Start the server

```sh
./bin/obscurad -addr :2222 -db obscura.db -host-key obscura_host_ed25519
```

`obscurad` generates the Ed25519 host key (PEM, `0600`) on first run if the path
does not exist, and prints the address it is listening on. Give the receiver and
sender the server's **host public key** (`obscura_host_ed25519.pub`-style line, or
the matching `known_hosts` entry) so they can pin it — Obscura never accepts an
unverified host key.

### 2. Create identities

Each user has one identity. Use a separate `--config-dir` per identity only when
running several on one machine (the demo below); normally you just run `obscura`
and it uses the default config dir.

```sh
# Receiver:
obscura --config-dir ~/.config/obscura-recv init
# -> prints the recovery seed ONCE on stderr (save it) and the public address on stdout

# Sender:
obscura --config-dir ~/.config/obscura-send init
```

Print an address again at any time (the receiver gives this string to the sender):

```sh
obscura --config-dir ~/.config/obscura-recv address
```

Recover an identity from its seed on a new machine:

```sh
obscura init --recover <seed-string>
```

### 3. Save the server details once (no more connection flags)

Instead of passing `--server` (and optionally `--host-key`) on every command, store
them in the config file (`~/.config/obscura/config.toml`, or the OS config dir):

```sh
obscura config set server localhost:2222

obscura config          # show the effective config and where each value came from
```

By default you configure **only the server**. On the first connection the client
pins the server's Ed25519 host key via **trust-on-first-use (TOFU)** and prints a
one-time notice with the pinned SHA256 fingerprint to stderr:

```text
┃ Host key pinned (first use)
┃ localhost:2222
┃ SHA256:p8f...q0
┃ trust-on-first-use; run 'obscura known-hosts forget localhost:2222' if it later changes legitimately
```

The pin is stored in `~/.config/obscura/known_hosts` (one line per server). Every
later connection must present the same key. If the key **changes**, the connection
is refused with a loud error showing both fingerprints:

```text
┃ Host key CHANGED for localhost:2222
┃ cached:    SHA256:p8f...q0
┃ presented: SHA256:zZ2...aA
┃ This may be a man-in-the-middle attack OR a legitimate server key rotation.
┃ The connection was refused and the cached key was NOT changed.
┃ If this change is expected, run 'obscura known-hosts forget localhost:2222' and retry.
```

Obscura never auto-accepts a changed key. Inspect or edit the TOFU cache with:

```sh
obscura known-hosts list                     # show pinned servers + SHA256 fingerprints
obscura known-hosts forget localhost:2222    # forget a pin; the next connect re-pins (TOFU)
```

#### Optional: hard-pin the host key up front

If you already know the server's host key you can pin it explicitly, which skips
TOFU entirely and treats any mismatch as a hard failure:

```sh
obscura config set host_key "$(cat obscura_host_ed25519.pub)"   # or: "$(just hostkey)"
```

`host_key` is the **server's** host public key (an `ssh-ed25519 AAAA...` line or a
path to a file with one), which the client pins — not your own key. When
`host_key` is set, the TOFU cache is neither read nor written for that
invocation; when it is unset, TOFU is used. After this, every command below is
just `obscura <command>` with no connection flags.

> **TOFU caveat.** TOFU protects you only after the *first* connection. A
> man-in-the-middle present at first contact would be pinned as if legitimate.
> Set `host_key` explicitly if you can verify the key out of band. Two different
> names for the same server (e.g. a hostname and its IP) are pinned as two
> independent entries.

### 4. Send a file

```sh
obscura send ./report.pdf --to <receiver-address> --name report.pdf
# -> prints the file id on stdout
```

Hide the encrypted package in a generated PNG carrier instead:

```sh
obscura send ./report.pdf --to <receiver-address> --png
```

> Only the **intended receiver** (the identity behind `--to`) can decrypt or
> extract the file. The sender cannot `receive` their own upload back as
> plaintext — the encryption and (for `--png`) the stego positions are keyed to
> the receiver. Sender and receiver must also point at the **same server**; a file
> id only exists on the server that received it.

### 5. List, receive, delete

```sh
# Receiver lists what was shared with them:
obscura list --received

# Receiver downloads, decrypts, and verifies to a path:
obscura receive <file_id> -o ./report.pdf

# Fetch the stored bytes verbatim (encrypted package or stego PNG), no decrypt:
obscura receive <file_id> -o ./stored.bin --raw

# Owner (sender) deletes the server copy:
obscura delete <file_id>
```

(When running multiple identities on one machine, prefix each command with
`--config-dir ~/.config/obscura-recv` or `...-send` as in step 2.)

### 6. Inspect a local package or PNG

```sh
obscura inspect ./encrypted.pkg    # prints non-secret metadata only
```

## Command reference

```text
obscura [global flags] <command> [args]

Commands:
  init [--recover <seed>] [--force]      create or recover the local identity
  address                                print this identity's public address
  send <path> --to <address> [--name <name>] [--png]
  list [--sent | --received]             list accessible server file records
  receive <file_id> [-o <path>] [--raw]  download, decrypt, and verify a file (--raw: stored bytes verbatim)
  delete <file_id>                       delete an owned server record
  inspect <package_or_png>               show non-secret metadata for a local file
  config [set <key> <value>]             show or edit the config file
  known-hosts list                       list trust-on-first-use pinned server keys
  known-hosts forget <server>            forget a pinned server key (re-pins on next use)

Global flags:
  --quiet                suppress progress cards; errors remain
  --no-color             plain progress without ANSI escapes
  --json                 emit one JSON result on stdout; no progress cards
  --server <host:port>   Obscura server address (or OBSCURA_SERVER)
  --host-key <value>     server host key line or path (or OBSCURA_HOST_KEY);
                         optional — trust-on-first-use is used when unset
  --config-dir <dir>     key store directory (or OBSCURA_CONFIG_DIR;
                         defaults to the user config dir)
```

`--host-key` is **optional**. When unset, the client trusts the server's host
key on first use (TOFU), pinning it in `<config-dir>/obscura/known_hosts` and
refusing any later key change. When set, it is a hard pin (a mismatch is a hard
failure) and the TOFU cache is neither read nor written. It accepts an
`authorized_keys`-style line, a `known_hosts`-style line, or a path to a file
containing one of those.

### Known hosts (trust-on-first-use)

With no `host_key` configured, the client pins the server's Ed25519 host key on
the first connection and stores it in `<config-dir>/obscura/known_hosts` (dir
`0700`, file `0600`). The format is one line per server:

```text
<normalized-server>\t<ssh-ed25519 AAAA... line>
```

The server is keyed by its normalized dial string (host lowercased, explicit
`:port`, whitespace trimmed), so `Relic-1:2222` and `relic-1:2222` are the same
entry, but a hostname and its IP address are two independent entries. The pin is
recorded only after the SSH handshake and public-key auth fully succeed. On a
changed key the connection is refused and the cache is never overwritten.

```text
obscura known-hosts list                     # print pinned servers + SHA256 fingerprints (stdout)
obscura known-hosts forget <server>          # remove a pin (atomic rewrite); next connect re-pins
```

`known-hosts forget` on a server with no cached entry exits non-zero with a clear
message so a typo is not mistaken for success. In `--json` mode both actions emit
a single JSON object on stdout.

### Config file

An optional config file lets you avoid repeating `--server` / `--host-key` /
`--config-dir` on every invocation. It lives alongside the seed at:

- Linux: `~/.config/obscura/config.toml`
- macOS: `~/Library/Application Support/obscura/config.toml`

more precisely `<config-dir>/obscura/config.toml`. The file is optional; its
absence is not an error. It is a small hand-edited file with two optional keys:

```toml
# obscura config
server = "host.example:2222"
host_key = "ssh-ed25519 AAAA..."   # optional; a path to a file with one such line also works
```

Supported syntax: blank lines, `#` comments, and `key = value` with optional
surrounding whitespace and optional double-quotes around the value. `host_key`
is **optional** (trust-on-first-use is used when it is unset) and accepts the
same forms as the `--host-key` flag (an `authorized_keys`/`known_hosts` line, or
a path to a file containing one). Unknown keys and malformed lines are a hard
error that names the file and line, so typos are caught rather than silently
ignored.

**Precedence (highest wins):** command-line flag > environment variable
(`OBSCURA_SERVER` / `OBSCURA_HOST_KEY`) > config file > built-in default. This
applies to `server` and `host_key`. `--config-dir` itself cannot come from the
config file (it determines where the file lives); it resolves as flag >
`OBSCURA_CONFIG_DIR` env > the default user config dir.

Manage the file with the `config` subcommand:

```text
obscura config                     # print the effective config and each value's source
obscura config set server host:2222
obscura config set host_key "ssh-ed25519 AAAA..."
```

`obscura config set` writes `<config-dir>/obscura/config.toml` (directory `0700`,
file `0600`, atomic temp+rename). It preserves the other known key but rewrites
the file with only the recognized keys, so hand-written comments are not
preserved. `obscura config` never prints secrets (the seed and private keys are
never touched); `server` and `host_key` are not secret.

### Output discipline

- **stdout** carries only the machine result: the address, the file id, the
  listing, inspect metadata, or (for `receive` without `-o`) the decrypted bytes
  (or the stored bytes with `--raw`). It is never decorated.
- **stderr** carries all progress cards, diagnostics, and errors.
- `--json` emits exactly one JSON object on stdout (including a structured error
  object on failure) and no cards anywhere.
- `receive` refuses to write binary output to a terminal; pass `-o <path>`.

## Server flags

```text
obscurad [flags]

  -addr <host:port>   listen address (default ":2222")
  -host-key <path>    Ed25519 host key (PEM); generated 0600 if missing
                      (default "obscura_host_ed25519")
  -db <path>          SQLite database path (default "obscura.db")
```

The server derives every caller's identity from the authenticated SSH key, accepts
only Ed25519 keys, allocates no PTY, spawns no shell, and enables no forwarding.

## NixOS / Nix (flake)

A `flake.nix` provides a Go dev shell and package builds. On a Nix machine (e.g.
`relic-1`) with flakes enabled:

```sh
nix develop            # dev shell with go, gopls, staticcheck, just, delve
just build             # then build as usual inside the shell

nix run .#obscura -- address        # run the client without a manual build
nix run .#obscurad -- -addr :2222   # run the server
nix build .#obscura                 # -> result/bin/obscura
```

The dev shell (`nix develop`) needs no extra setup. Building the package with
`nix build`/`nix run` needs the Go module `vendorHash` in `flake.nix`: run the
command once, and Nix will fail printing the correct `got: sha256-...` — paste
that into `flake.nix` (`vendorHash`) and rerun. Alternatively run `go mod vendor`
in the source tree and set `vendorHash = null;`.

Go 1.26 (required by `go.mod`) is on `nixpkgs-unstable`, which the flake pins.

## Development

```sh
just            # list tasks
just build      # build both binaries into ./bin
just test       # go test -race ./...
just lint       # go vet + gofmt check
just check      # build + lint + test (pre-commit gate)
just tidy       # go mod tidy
just clean      # remove ./bin and local *.db / host keys
```

Server helpers: `just run-server` (run obscurad locally) and
`just hostkey [path=...]` (print the pinned host public key line for a host key
PEM, default `./obscura_host_ed25519`).

## Security notes

- Encryption, decryption, and all secret material stay on the client. The server
  stores ciphertext plus metadata (sender, receiver, size, timestamps, name,
  carrier type).
- A received file is written only after AEAD authentication, bounded decompression,
  and BLAKE3 verification succeed, and then only via an atomic temp-file rename.
- PNG steganography provides concealment against casual inspection, not against
  specialist analysis, and is not robust to pixel changes.
- Deleting a file from the server does not revoke a copy a receiver already
  downloaded.
- Only the intended receiver can decrypt or extract a file; the sender cannot
  recover their own upload as plaintext. `receive --raw` returns the stored
  ciphertext/stego bytes verbatim and applies no decryption or verification.

## Status

Core layers are implemented and tested end-to-end (identity, package format, PNG
carrier, storage, SSH server/routing, SSH client, key store, terminal UI, and the
`obscura` CLI). See the commit history for the per-feature build order.
