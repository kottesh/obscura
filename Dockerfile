# Obscura server (obscurad) container image.
#
# Multi-stage build: a static, cgo-free Linux binary (modernc.org/sqlite is pure
# Go, so CGO_ENABLED=0 yields a fully static binary) shipped in a scratch image.
# Built and run with Apple's `container` CLI or any OCI builder.

# ---- build stage ----
FROM golang:1.26 AS build

# Target architecture is supplied by the builder (arm64 on Apple Silicon).
ARG TARGETARCH=arm64
ARG TARGETOS=linux

WORKDIR /src

# Cache module downloads before copying the full source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Fully static, stripped binary. No cgo, no external libc.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/obscurad ./cmd/obscurad

# ---- runtime stage ----
FROM scratch

# Non-root numeric user (no /etc/passwd in scratch; run by uid).
USER 65532:65532

# Persistent state lives here; mount a volume at run time so the SQLite database
# and generated host key survive container restarts.
WORKDIR /data

COPY --from=build /out/obscurad /obscurad

# SSH transport port (matches the -addr default below).
EXPOSE 2222

# The database and host key are written under /data (a mounted volume). The host
# key is generated on first start if absent.
ENTRYPOINT ["/obscurad"]
CMD ["-addr", ":2222", "-db", "/data/obscura.db", "-host-key", "/data/obscura_host_ed25519"]
