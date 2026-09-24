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

// Environment variable names for server address and host key (spec 7/8.4).
// Flags take precedence over these.
const (
	envServer  = "OBSCURA_SERVER"
	envHostKey = "OBSCURA_HOST_KEY"
)

// usageText is the top-level usage string shown for help and usage errors.
const usageText = `usage: obscura [global flags] <command> [args]

Commands:
  init [--recover <seed>] [--force]      create or recover the local identity
  address                                print this identity's public address
  send <path> --to <address> [--name <name>] [--png]
                                         encrypt and upload a file
  list [--sent | --received]             list accessible server file records
  receive <file_id> [-o <path>]          download, decrypt, and verify a file
  delete <file_id>                       delete an owned server record
  inspect <package_or_png>               show non-secret metadata for a local file

Global flags:
  --quiet             suppress progress cards; errors remain
  --no-color          plain progress without ANSI escapes
  --json              emit one JSON result on stdout; no progress cards
  --server <host:port>   Obscura server address (or OBSCURA_SERVER)
  --host-key <value>     server host key line or path (or OBSCURA_HOST_KEY)
  --config-dir <dir>     key store directory (defaults to the user config dir)`

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
	g := globalFlags{
		server:  getenv(envServer),
		hostKey: getenv(envHostKey),
	}

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
			continue
		case "--host-key", "-host-key":
			v, next, err := flagValue(args, i, name, inlineVal, hasInline)
			if err != nil {
				return globalFlags{}, nil, err
			}
			g.hostKey, i = v, next
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

	if g.configDir == "" {
		dir, err := keystore.DefaultDir()
		if err != nil {
			return globalFlags{}, nil, err
		}
		g.configDir = dir
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
		return "", usagef("no server configured; set --server or %s", envServer)
	}
	return g.server, nil
}

// hostKeyCallback builds the SSH host-key verification callback from the
// configured host key value (spec 6.1: pin the server host key). The value is
// an SSH public key line, a known-hosts style line, or a path to a file
// containing one of those. A missing host key is a usage error rather than a
// silent insecure default.
func (g globalFlags) hostKeyCallback() (gossh.HostKeyCallback, error) {
	if g.hostKey == "" {
		return nil, usagef("no host key configured; set --host-key or %s", envHostKey)
	}
	pub, err := parseHostKey(g.hostKey)
	if err != nil {
		return nil, err
	}
	return gossh.FixedHostKey(pub), nil
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
