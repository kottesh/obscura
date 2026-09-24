// Command hostpub prints the SSH authorized_keys-style public key line for an
// Ed25519 host private key (PEM/PKCS#8), for use with the obscura client's
// --host-key flag. It reads the key path from the first argument.
//
//	go run ./tools/hostpub .container-data/obscura_host_ed25519
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hostpub <ed25519-host-key-pem>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "hostpub:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("not an Ed25519 key: %T", key)
	}
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	// MarshalAuthorizedKey already appends a trailing newline.
	fmt.Print(string(ssh.MarshalAuthorizedKey(pub)))
	return nil
}
