# Obscura task runner. Run `just` to list tasks.

# Directory for built binaries.
bin := "bin"

# List available tasks.
default:
    @just --list

# Build both binaries into ./bin.
build:
    mkdir -p {{bin}}
    go build -o {{bin}}/obscura  ./cmd/obscura
    go build -o {{bin}}/obscurad ./cmd/obscurad

# Run the full test suite with the race detector.
test:
    go test -race -count=1 ./...

# Run tests without the race detector (faster).
test-fast:
    go test -count=1 ./...

# Static analysis: go vet plus a gofmt formatting check.
lint:
    go vet ./...
    @unformatted="$(gofmt -l .)"; \
        if [ -n "$unformatted" ]; then \
            echo "gofmt needs to run on:"; echo "$unformatted"; exit 1; \
        fi

# Apply gofmt to the whole module.
fmt:
    gofmt -w .

# Reconcile module dependencies.
tidy:
    go mod tidy

# Pre-commit gate: build, lint, and test.
check: build lint test

# Run the server locally (override with `just run-server addr=:2222 db=obscura.db`).
run-server addr=":2222" db="obscura.db" host_key="obscura_host_ed25519":
    go run ./cmd/obscurad -addr {{addr}} -db {{db}} -host-key {{host_key}}

# Print the obscura CLI help.
help:
    go run ./cmd/obscura help

# Remove built binaries and local runtime artifacts (DB, generated host keys).
clean:
    rm -rf {{bin}}
    rm -f obscura.db obscura.db-shm obscura.db-wal
    rm -f obscura_host_ed25519 obscura_host_ed25519.pub

# ---- Apple container (macOS) ----

image := "obscura/obscurad:dev"
data  := justfile_directory() / ".container-data"

# Build the obscurad server image with Apple's `container` CLI.
# Requires: container system start (kernel + Rosetta-disabled builder, see README).
container-build:
    container build --tag {{image}} --file Dockerfile .

# Run the server container detached, publishing :2222 and persisting state under
# ./.container-data (SQLite DB + generated host key survive restarts).
container-run: container-build
    mkdir -p "{{data}}"
    container run -d --name obscurad -p 2222:2222 -v "{{data}}":/data {{image}}
    @container list | grep obscurad || true

# Tail the server container logs.
container-logs:
    container logs -f obscurad

# Print the pinned host public key line clients need for --host-key.
container-hostkey:
    @test -f "{{data}}/obscura_host_ed25519" || (echo "no host key yet; run 'just container-run' first" && exit 1)
    @go run ./tools/hostpub "{{data}}/obscura_host_ed25519"

# Stop and remove the server container (state under ./.container-data is kept).
container-stop:
    -container stop obscurad
    -container rm obscurad
