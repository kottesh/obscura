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

## Run the server in a container (macOS)

The server ships as a static, cgo-free Linux binary in a `scratch` image, built and
run with [Apple's `container` CLI](https://github.com/apple/container).

One-time setup:

```sh
# Start the container system (installs a Linux kernel on first run).
container system start

# Disable the Rosetta-backed builder shim (see apple/container#103), then restart.
mkdir -p ~/.config/container
printf '[build]\nrosetta = false\n' >> ~/.config/container/config.toml
container system stop && container system start
```

Build and run:

```sh
just container-build     # build obscura/obscurad:dev
just container-run       # run detached, publish :2222, persist ./.container-data
just container-logs      # follow logs
just container-stop      # stop + remove (state under ./.container-data is kept)
```

The SQLite database and the generated Ed25519 host key live on the mounted volume
(`./.container-data`), so they survive container restarts. Print the host key line
clients need to pin:

```sh
just container-hostkey   # -> ssh-ed25519 AAAA... (pass to --host-key)
```

Point a client at the container (use the container's IP from `container list`, or a
published host address):

```sh
obscura --server <container-ip>:2222 --host-key "$(just container-hostkey)" \
  --config-dir ~/.config/obscura-send send ./report.pdf --to <receiver-address>
```

Raw equivalents without `just`:

```sh
container build --tag obscura/obscurad:dev --file Dockerfile .
container run -d --name obscurad -p 2222:2222 -v "$PWD/.container-data":/data obscura/obscurad:dev
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

```sh
# Receiver (use a separate config dir per identity in this single-machine demo):
obscura --config-dir ~/.config/obscura-recv init
# -> prints the recovery seed ONCE on stderr (save it) and the public address on stdout

# Sender:
obscura --config-dir ~/.config/obscura-send init
```

Print an address again at any time:

```sh
obscura --config-dir ~/.config/obscura-recv address
```

Recover an identity from its seed on a new machine:

```sh
obscura init --recover <seed-string>
```

### 3. Send a file

```sh
obscura \
  --server localhost:2222 \
  --host-key "$(cat obscura_host_ed25519.pub)" \
  --config-dir ~/.config/obscura-send \
  send ./report.pdf --to <receiver-address> --name report.pdf
# -> prints the file id on stdout
```

Hide the encrypted package in a generated PNG carrier instead:

```sh
obscura ... send ./report.pdf --to <receiver-address> --png
```

### 4. List, receive, delete

```sh
# Receiver lists what was shared with them:
obscura ... --config-dir ~/.config/obscura-recv list --received

# Receiver downloads, decrypts, and verifies to a path:
obscura ... --config-dir ~/.config/obscura-recv receive <file_id> -o ./report.pdf

# Owner (sender) deletes the server copy:
obscura ... --config-dir ~/.config/obscura-send delete <file_id>
```

### 5. Inspect a local package or PNG

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
  receive <file_id> [-o <path>]          download, decrypt, and verify a file
  delete <file_id>                       delete an owned server record
  inspect <package_or_png>               show non-secret metadata for a local file
  config [set <key> <value>]             show or edit the config file

Global flags:
  --quiet                suppress progress cards; errors remain
  --no-color             plain progress without ANSI escapes
  --json                 emit one JSON result on stdout; no progress cards
  --server <host:port>   Obscura server address (or OBSCURA_SERVER)
  --host-key <value>     server host key line or path (or OBSCURA_HOST_KEY)
  --config-dir <dir>     key store directory (or OBSCURA_CONFIG_DIR;
                         defaults to the user config dir)
```

`--host-key` accepts an `authorized_keys`-style line, a `known_hosts`-style line,
or a path to a file containing one of those.

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
host_key = "ssh-ed25519 AAAA..."   # or a path to a file with one such line
```

Supported syntax: blank lines, `#` comments, and `key = value` with optional
surrounding whitespace and optional double-quotes around the value. `host_key`
accepts the same forms as the `--host-key` flag (an `authorized_keys`/
`known_hosts` line, or a path to a file containing one). Unknown keys and
malformed lines are a hard error that names the file and line, so typos are
caught rather than silently ignored.

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
  listing, inspect metadata, or (for `receive` without `-o`) the raw decrypted
  bytes. It is never decorated.
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

Container tasks (macOS, Apple `container`): `just container-build`,
`just container-run`, `just container-logs`, `just container-hostkey`,
`just container-stop`.

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

## Status

Core layers are implemented and tested end-to-end (identity, package format, PNG
carrier, storage, SSH server/routing, SSH client, key store, terminal UI, and the
`obscura` CLI). See the commit history for the per-feature build order.
