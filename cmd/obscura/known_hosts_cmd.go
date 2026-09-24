package main

import (
	"context"
	"fmt"
	"text/tabwriter"
)

// cmdKnownHosts implements 'obscura known-hosts <action>' for inspecting and
// editing the trust-on-first-use (TOFU) cache at <config-dir>/obscura/known_hosts.
//
//	obscura known-hosts list
//	    Print cached entries (server + SHA256 fingerprint) to stdout. --json
//	    emits one JSON object with an "entries" array.
//
//	obscura known-hosts forget <server>
//	    Remove the cached pin for <server> (normalized match) via an atomic
//	    rewrite. A subsequent connection re-runs TOFU (re-pins). Forgetting a
//	    server with no cached entry exits non-zero with a clear message so a
//	    typo is not silently swallowed.
//
// Stream discipline (spec 8.3): the machine result goes to stdout; progress and
// errors go to stderr; --json emits one object on stdout. Nothing sensitive
// (there are no secrets here; host keys are public) and no cards land on stdout.
func cmdKnownHosts(_ context.Context, env *cmdEnv, args []string) error {
	if len(args) == 0 {
		return usagef("known-hosts: expected an action (list | forget <server>)")
	}
	action, rest := args[0], args[1:]
	switch action {
	case "list":
		if len(rest) != 0 {
			return usagef("known-hosts list: takes no arguments")
		}
		return knownHostsList(env)
	case "forget":
		if len(rest) != 1 {
			return usagef("known-hosts forget: expected <server>, got %d argument(s)", len(rest))
		}
		return knownHostsForget(env, rest[0])
	default:
		return usagef("known-hosts: unknown action %q; use 'list' or 'forget <server>'", action)
	}
}

// knownHostsList prints the cached pins. Each entry shows the normalized server
// and its SHA256 fingerprint; an unparseable cached line surfaces as a usage
// error rather than a silent skip.
func knownHostsList(env *cmdEnv) error {
	entries, err := loadKnownHosts(env.g.configDir)
	if err != nil {
		return err
	}

	type item struct {
		server      string
		fingerprint string
	}
	items := make([]item, 0, len(entries))
	for _, e := range entries {
		pub, perr := parseKeyLine(e.keyLine)
		if perr != nil {
			return usagef("known_hosts entry for %s is unparseable: %v", e.server, perr)
		}
		items = append(items, item{server: e.server, fingerprint: fingerprintSHA256(pub)})
	}

	if env.g.mode == modeJSON() {
		out := make([]map[string]any, 0, len(items))
		for _, it := range items {
			out = append(out, map[string]any{
				"server":      it.server,
				"fingerprint": it.fingerprint,
			})
		}
		return writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"command": "known-hosts list",
			"entries": out,
		})
	}

	if len(items) == 0 {
		env.r.Stage("No pinned hosts", "the trust-on-first-use cache is empty")
		return nil
	}
	tw := tabwriter.NewWriter(env.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tFINGERPRINT")
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\n", it.server, it.fingerprint)
	}
	_ = tw.Flush()
	return nil
}

// knownHostsForget removes a server's cached pin. A missing entry is a clear
// non-zero usage error so a typo does not masquerade as success.
func knownHostsForget(env *cmdEnv, server string) error {
	normServer := normalizeServer(server)
	removed, err := forgetKnownHost(env.g.configDir, normServer)
	if err != nil {
		return err
	}
	if !removed {
		return usagef("known-hosts forget: no pinned host key for %s", normServer)
	}

	if env.g.mode == modeJSON() {
		return writeJSON(env.stdout, map[string]any{
			"version":   jsonVersion,
			"command":   "known-hosts forget",
			"server":    normServer,
			"forgotten": true,
		})
	}

	env.r.Success("Host key forgotten", fmt.Sprintf("%s\nnext connection will re-pin via trust-on-first-use", normServer))
	return nil
}
