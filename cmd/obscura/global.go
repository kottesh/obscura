package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kottesh/obscura/internal/keystore"
	"github.com/kottesh/obscura/internal/ui"
	gossh "golang.org/x/crypto/ssh"
)

// Environment variable names for server address, host key, and config dir
// (spec 7/8.4). Flags take precedence over these, and these take precedence
// over the optional config file.
const (
	envServer    = "OBSCURA_SERVER"
	envHostKey   = "OBSCURA_HOST_KEY"
	envConfigDir = "OBSCURA_CONFIG_DIR"
)

// usageText is the top-level usage string shown for help and usage errors.
const usageText = `usage: obscura [global flags] <command> [args]

Commands:
  init [--recover <seed>] [--force]      create or recover the local identity
  address                                print this identity's public address
  send <path> --to <address> [--name <name>] [--png]
                                         encrypt and upload a file
  list [--sent | --received]             list accessible server file records
  receive <file_id> [-o <path>] [--raw]  download, decrypt, and verify a file (--raw: stored bytes verbatim)
  delete <file_id>                       delete an owned server record
  inspect <package_or_png>               show non-secret metadata for a local file

  config [set <key> <value>]             show or edit the config file
  known-hosts list                       list trust-on-first-use pinned server keys
  known-hosts forget <server>            forget a pinned server key (re-pins on next use)

Global flags:
  --quiet             suppress progress cards; errors remain
  --no-color          plain progress without ANSI escapes
  --json              emit one JSON result on stdout; no progress cards
  --server <host:port>   Obscura server address (or OBSCURA_SERVER)
  --host-key <value>     server host key line or path (or OBSCURA_HOST_KEY).
                         Optional: when unset, trust-on-first-use pins the
                         server key on first connection; when set, it is a hard
                         pin and a mismatch is a hard failure.
  --config-dir <dir>     key store directory (or OBSCURA_CONFIG_DIR;
                         defaults to the user config dir)

Config file (optional):
  <config-dir>/obscura/config.toml may set 'server' and 'host_key'. Precedence,
  highest first: flag > environment > config file > built-in default. 'host_key'
  is optional; without it the client uses a trust-on-first-use cache at
  <config-dir>/obscura/known_hosts.`

// globalFlags holds parsed global options shared by every subcommand.
type globalFlags struct {
	mode      ui.Mode
	quiet     bool
	noColor   bool
	json      bool
	server    string // resolved from --server or OBSCURA_SERVER
	hostKey   string // resolved from --host-key or OBSCURA_HOST_KEY
	configDir string // resolved from --config-dir or keystore.DefaultDir()
}

// parseGlobal extracts the global flags that may appear before the subcommand
// and returns the remaining (command + command args) tokens. Global flags are
// only recognized before the first non-flag token so that per-command flags of
// the same spelling (e.g. a file path) are never swallowed. Unknown flags in
// the global position are a usage error.
func parseGlobal(args []string, getenv func(string) string) (globalFlags, []string, error) {
	g := globalFlags{}
	// Track whether server/host_key came from flags so config-file values only
	// fill genuinely-unset fields (flag > env > file precedence).
	var serverFromFlag, hostKeyFromFlag bool

	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") {
			break // first positional token is the command
		}

		name, inlineVal, hasInline := splitFlag(a)
		switch name {
		case "--quiet", "-quiet":
			g.quiet = true
		case "--no-color", "-no-color":
			g.noColor = true
		case "--json", "-json":
			g.json = true
		case "--server", "-server":
			v, next, err := flagValue(args, i, name, inlineVal, hasInline)
			if err != nil {
				return globalFlags{}, nil, err
			}
			g.server, i = v, next
			serverFromFlag = true
			continue
		case "--host-key", "-host-key":
			v, next, err := flagValue(args, i, name, inlineVal, hasInline)
			if err != nil {
				return globalFlags{}, nil, err
			}
			g.hostKey, i = v, next
			hostKeyFromFlag = true
			continue
		case "--config-dir", "-config-dir":
			v, next, err := flagValue(args, i, name, inlineVal, hasInline)
			if err != nil {
				return globalFlags{}, nil, err
			}
			g.configDir, i = v, next
			continue
		default:
			return globalFlags{}, nil, usagef("unknown global flag %q", a)
		}
		i++
	}

	g.mode = resolveMode(g)

	// Resolve the config directory FIRST (flag > env > default) because it
	// determines where the optional config file lives. --config-dir itself can
	// never come from the config file.
	if g.configDir == "" {
		if env := getenv(envConfigDir); env != "" {
			g.configDir = env
		} else {
			dir, err := keystore.DefaultDir()
			if err != nil {
				return globalFlags{}, nil, err
			}
			g.configDir = dir
		}
	}

	// Apply env after flags: env fills fields not set by a flag.
	if !serverFromFlag {
		g.server = getenv(envServer)
	}
	if !hostKeyFromFlag {
		g.hostKey = getenv(envHostKey)
	}

	// Load the optional config file and fill server/host_key only if still empty
	// after flag+env. A malformed file is an actionable usage error.
	cfg, _, err := loadConfig(g.configDir)
	if err != nil {
		return globalFlags{}, nil, err
	}
	if g.server == "" {
		g.server = cfg.server
	}
	if g.hostKey == "" {
		g.hostKey = cfg.hostKey
	}

	return g, args[i:], nil
}

// splitFlag splits "--name=value" into ("--name", "value", true); a bare
// "--name" yields ("--name", "", false).
func splitFlag(a string) (name, val string, hasVal bool) {
	if eq := strings.IndexByte(a, '='); eq >= 0 {
		return a[:eq], a[eq+1:], true
	}
	return a, "", false
}

// flagValue resolves a value flag's value either from its inline "=value" form
// or the following token, returning the next index to resume scanning at.
func flagValue(args []string, i int, name, inlineVal string, hasInline bool) (string, int, error) {
	if hasInline {
		return inlineVal, i + 1, nil
	}
	if i+1 >= len(args) {
		return "", 0, usagef("flag %s requires a value", name)
	}
	return args[i+1], i + 2, nil
}

// resolveMode maps the three mode flags to a single ui.Mode. JSON wins over
// quiet and no-color because JSON output must be uncontaminated; quiet wins
// over no-color because quiet already implies no progress decoration.
func resolveMode(g globalFlags) ui.Mode {
	switch {
	case g.json:
		return ui.ModeJSON
	case g.quiet:
		return ui.ModeQuiet
	case g.noColor:
		return ui.ModeNoColor
	default:
		return ui.ModeNormal
	}
}

// stderrFile returns the *os.File backing w when w is an *os.File, else nil so
// the renderer disables TTY-dependent decoration. Tests pass a bytes.Buffer and
// correctly get plain output.
func stderrFile(w io.Writer) *os.File {
	if f, ok := w.(*os.File); ok {
		return f
	}
	return nil
}

// requireServer resolves the server address, returning a usage error if none is
// configured via flag or environment.
func (g globalFlags) requireServer() (string, error) {
	if g.server == "" {
		return "", usagef("no server configured; set --server, %s, or 'server' in %s",
			envServer, configPath(g.configDir))
	}
	return g.server, nil
}

// hostKeyVerifier bundles the SSH host-key verification callback with an
// optional TOFU commit hook. The commit hook is non-nil only in TOFU mode and
// only fires meaningfully after a successful dial (it records a first-use pin).
// In explicit-pin mode commit is nil: the TOFU cache is neither read nor
// written.
type hostKeyVerifier struct {
	callback gossh.HostKeyCallback
	// commit records a first-use pin after a successful dial. It is safe to call
	// even when no first-use occurred (then it is a no-op) and safe to call when
	// nil via commitHostKey. It also emits the one-time first-use notice.
	commit func() error
}

// commitHostKey runs v.commit if present, else is a no-op. Commands call it
// after a successful client operation so a first-use pin is recorded only once
// the handshake and auth fully succeeded.
func (v hostKeyVerifier) commitHostKey() error {
	if v.commit == nil {
		return nil
	}
	return v.commit()
}

// hostKeyCallback builds the SSH host-key verification for this invocation
// (spec 6.1). Precedence is per-invocation and mutually exclusive:
//
//   - If host_key is explicitly configured (--host-key / OBSCURA_HOST_KEY /
//     config 'host_key'), hard-pin it with gossh.FixedHostKey. The TOFU cache
//     is neither read nor written, and a mismatch is a hard failure.
//   - If host_key is unset, use trust-on-first-use against
//     <config-dir>/obscura/known_hosts. host_key is optional in this mode; the
//     first observed key is pinned (recorded post-dial by commit), later keys
//     must match, and a changed key aborts the connection.
//
// The renderer r is used to emit the one-time first-use pin notice to stderr;
// it is suppressed in quiet and JSON modes.
func (g globalFlags) hostKeyCallback(r *ui.Renderer, server string) (hostKeyVerifier, error) {
	if g.hostKey != "" {
		pub, err := parseHostKey(g.hostKey)
		if err != nil {
			return hostKeyVerifier{}, err
		}
		return hostKeyVerifier{callback: gossh.FixedHostKey(pub)}, nil
	}

	// TOFU mode: load the cache, build the capturing callback, and return a
	// commit hook that records a first-use pin after a successful dial.
	normServer := normalizeServer(server)
	entries, err := loadKnownHosts(g.configDir)
	if err != nil {
		return hostKeyVerifier{}, err
	}
	cb, res := tofuHostKeyCallback(normServer, entries)
	commit := func() error {
		if !res.firstUse || res.key == nil {
			return nil
		}
		if err := recordKnownHost(g.configDir, normServer, hostKeyLine(res.key)); err != nil {
			return err
		}
		// One-time first-use notice to stderr as a progress stage, so it is
		// suppressed in both quiet and JSON modes (ProgressEnabled). stdout is
		// never touched.
		r.Stage("Host key pinned (first use)",
			fmt.Sprintf("%s\n%s\ntrust-on-first-use; run 'obscura known-hosts forget %s' if it later changes legitimately",
				normServer, fingerprintSHA256(res.key), normServer))
		return nil
	}
	return hostKeyVerifier{callback: cb, commit: commit}, nil
}

// parseHostKey parses a host key from either a literal SSH public key/known-
// hosts line or a path to a file containing such a line. The parsed key must be
// Ed25519 (spec 6.1). It never falls back to an insecure callback.
func parseHostKey(value string) (gossh.PublicKey, error) {
	line := value
	if data, err := os.ReadFile(value); err == nil {
		line, err = firstKeyLine(data)
		if err != nil {
			return nil, err
		}
	}
	pub, err := parseKeyLine(line)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	if pub.Type() != gossh.KeyAlgoED25519 {
		return nil, fmt.Errorf("host key must be Ed25519, got %s", pub.Type())
	}
	return pub, nil
}

// firstKeyLine returns the first non-empty, non-comment line of a host key
// file.
func firstKeyLine(data []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("host key file contains no key line")
}

// parseKeyLine parses a single SSH public key line. It accepts both an
// authorized_keys style line ("ssh-ed25519 AAAA... [comment]") and a
// known-hosts style line ("host ssh-ed25519 AAAA... [comment]") by trying the
// authorized-keys parser first and, on failure, dropping a leading host field.
func parseKeyLine(line string) (gossh.PublicKey, error) {
	line = strings.TrimSpace(line)
	if pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line)); err == nil {
		return pub, nil
	}
	// known-hosts style: strip the leading host pattern field and retry.
	if fields := strings.Fields(line); len(fields) >= 3 {
		rest := strings.Join(fields[1:], " ")
		if pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(rest)); err == nil {
			return pub, nil
		}
	}
	return nil, errors.New("not a valid SSH public key line")
}
