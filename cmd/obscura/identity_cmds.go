package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/keystore"
)

// cmdInit implements 'obscura init [--recover <seed>] [--force]' (spec 7).
// On success the public address is printed to stdout and, for a freshly
// generated identity, the recovery seed is displayed once on stderr with a
// clear "save this" note. The seed never goes to stdout and is never logged.
func cmdInit(_ context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("init")
	var (
		recover string
		force   bool
	)
	fs.StringVar(&recover, "recover", "", "recover from a base58 seed backup")
	fs.BoolVar(&force, "force", false, "overwrite an existing identity")
	if err := parseCmd(fs, args, 0, 0); err != nil {
		return err
	}

	var (
		id        *identity.Identity
		err       error
		recovered bool
	)
	if recover != "" {
		seed, derr := keystore.DecodeSeed(recover)
		if derr != nil {
			return usagef("invalid recovery seed: %v", derr)
		}
		env.r.Crypto("Recovering identity", "restoring Ed25519 and X25519 keys from seed")
		id, err = keystore.Recover(env.g.configDir, seed, force)
		recovered = true
	} else {
		env.r.Crypto("Generating identity", "new master seed · Ed25519 + X25519 keys")
		id, err = keystore.Init(env.g.configDir, force)
	}
	if err != nil {
		return err
	}

	addr, err := id.Address()
	if err != nil {
		return err
	}

	if env.g.mode == modeJSON() {
		return writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"command": "init",
			"address": addr,
		})
	}

	// The recovery seed is shown once, on stderr, only for a newly generated
	// identity. On recovery the user already has the seed, so we do not echo it.
	if !recovered {
		env.r.Warn("Save your recovery seed", fmt.Sprintf(
			"This is shown once and cannot be recovered if lost.\nseed: %s",
			keystore.EncodeSeed(id.Seed),
		))
	}
	env.r.Success("Identity ready", "address printed to stdout")

	fmt.Fprintln(env.stdout, addr)
	return nil
}

// cmdAddress implements 'obscura address' (spec 7): print base58(sign_pk ||
// box_pk) to stdout, nothing else.
func cmdAddress(_ context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("address")
	if err := parseCmd(fs, args, 0, 0); err != nil {
		return err
	}

	addr, err := keystore.Address(env.g.configDir)
	if err != nil {
		return err
	}

	if env.g.mode == modeJSON() {
		return writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"command": "address",
			"address": addr,
		})
	}

	fmt.Fprintln(env.stdout, addr)
	return nil
}

// jsonVersion is the version tag included in every JSON result (spec 8.3 "one
// versioned JSON value").
const jsonVersion = 1

// writeJSON encodes v as a single compact JSON object followed by a newline to
// stdout. It is the only thing a command writes to stdout in --json mode.
func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
