// Command obscura is the Obscura client CLI (spec section 7). It handles local
// key management, client-side encryption, optional PNG steganography, upload
// and download over SSH, and local decryption. Private key material, shared
// secrets, and plaintext never leave the machine and never go to stdout.
//
// # Stream discipline (spec 8.3)
//
// stdout carries only the machine result of a command: the address, the file
// id, the listing, downloaded bytes (receive without -o on a non-TTY), or
// inspect metadata. Every progress card, stage update, warning, and error goes
// to stderr through internal/ui. In --json mode exactly one JSON object is
// written to stdout and no cards are emitted anywhere.
//
// # Server address and host key
//
// The server address comes from --server, else the OBSCURA_SERVER environment
// variable. The host key comes from --host-key, else OBSCURA_HOST_KEY. Flags
// take precedence over environment. The host key value is either an SSH public
// key line ("ssh-ed25519 AAAA..."), a known-hosts style line
// ("host ssh-ed25519 AAAA..."), or a path to a file containing one of those.
package main

import (
	"context"
	"os"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}
