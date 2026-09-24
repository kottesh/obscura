package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// knownHostsFileName is the trust-on-first-use (TOFU) cache within appDir. It
// records one pinned host key per server so that after the first connection the
// client detects a changed key (spec 6.1). It lives at
// <config-dir>/obscura/known_hosts (dir 0700, file 0600).
const knownHostsFileName = "known_hosts"

// knownHostsPath returns the full path to the TOFU cache for a resolved config
// base directory: <configDir>/obscura/known_hosts.
func knownHostsPath(configDir string) string {
	return filepath.Join(configDir, appDir, knownHostsFileName)
}

// normalizeServer canonicalizes a server dial string so the same server is
// keyed identically at write and lookup: leading/trailing whitespace is
// trimmed, the host is lowercased, and an explicit :port is ensured (a bare
// host with no port is returned trimmed+lowercased as-is; a value without a
// splittable host:port is lowercased and trimmed). Two syntactically different
// spellings of one host (e.g. a name vs its IP) remain distinct keys by design
// — TOFU pins the exact dial string, not the resolved endpoint.
func normalizeServer(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// No explicit port (or an unparseable value): lowercase the whole thing.
		return strings.ToLower(s)
	}
	host = strings.ToLower(host)
	// SplitHostPort strips the brackets around an IPv6 literal; restore them so
	// the normalized form round-trips as a valid dial string.
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// fingerprintSHA256 renders an SSH public key's OpenSSH-style SHA256
// fingerprint: "SHA256:" + unpadded base64 of sha256(key.Marshal()). This is
// the same form OpenSSH prints, so users can compare it against server-side
// tooling.
func fingerprintSHA256(key gossh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// knownHostEntry is one pinned server: the normalized dial string and the
// server's authorized_keys-style host key line.
type knownHostEntry struct {
	// server is the normalized dial string (see normalizeServer).
	server string
	// keyLine is the trimmed "ssh-ed25519 AAAA..." line for the pinned key.
	keyLine string
}

// tofuResult carries what the host-key callback observed during a handshake so
// the caller can act after the dial fully succeeds. The callback never writes
// the cache itself; it only records the presented key and whether this was a
// first-use (absent from cache) observation.
type tofuResult struct {
	// firstUse is true when the server was absent from the cache and the
	// presented key was accepted for the first time.
	firstUse bool
	// key is the host key the server presented (only meaningful on firstUse).
	key gossh.PublicKey
}

// changedHostKeyError aborts a handshake when the presented host key differs
// from the cached pin. It carries both fingerprints so the CLI can render a
// loud, actionable change-detection failure (spec 6.1). It never triggers an
// automatic overwrite.
type changedHostKeyError struct {
	server      string
	cachedFP    string
	presentedFP string
}

func (e *changedHostKeyError) Error() string {
	return fmt.Sprintf("host key for %s changed: cached %s, presented %s", e.server, e.cachedFP, e.presentedFP)
}

// loadKnownHosts reads and parses the TOFU cache. A missing file is not an
// error: it returns an empty slice. Each line is "<normalized-server>\t<key
// line>"; blank lines and '#' comments are ignored. A malformed line is a
// usage error naming the path.
func loadKnownHosts(configDir string) ([]knownHostEntry, error) {
	path := knownHostsPath(configDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, usagef("read known_hosts %s: %v", path, err)
	}
	var entries []knownHostEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			return nil, usagef("known_hosts %s line %d: expected '<server>\\t<key line>', got %q", path, lineNo, raw)
		}
		server := strings.TrimSpace(line[:tab])
		keyLine := strings.TrimSpace(line[tab+1:])
		if server == "" || keyLine == "" {
			return nil, usagef("known_hosts %s line %d: empty server or key line", path, lineNo)
		}
		entries = append(entries, knownHostEntry{server: server, keyLine: keyLine})
	}
	if err := sc.Err(); err != nil {
		return nil, usagef("read known_hosts %s: %v", path, err)
	}
	return entries, nil
}

// lookupKnownHost returns the cached entry for a normalized server, or ok=false
// if absent.
func lookupKnownHost(entries []knownHostEntry, normServer string) (knownHostEntry, bool) {
	for _, e := range entries {
		if e.server == normServer {
			return e, true
		}
	}
	return knownHostEntry{}, false
}

// writeKnownHosts serializes entries to the TOFU cache via an atomic
// temp+rename, creating the directory 0700 and the file 0600. Entries are
// sorted by server for a stable file. It rewrites the WHOLE file so a
// concurrent write for a different server is the only thing that can be
// clobbered (last-writer-wins per file); per-server records survive because the
// caller does a read-modify-write of the whole set.
func writeKnownHosts(configDir string, entries []knownHostEntry) error {
	dir := filepath.Join(configDir, appDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	sorted := append([]knownHostEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].server < sorted[j].server })

	var b strings.Builder
	b.WriteString("# obscura known_hosts (trust-on-first-use cache; one line per server)\n")
	for _, e := range sorted {
		fmt.Fprintf(&b, "%s\t%s\n", e.server, e.keyLine)
	}
	return writeFileAtomic(knownHostsPath(configDir), []byte(b.String()), 0o600)
}

// recordKnownHost does a read-modify-write of the whole cache, setting or
// replacing the entry for normServer with keyLine. This is the post-dial commit
// invoked only after a successful handshake+auth (spec 6.1: record after Dial).
func recordKnownHost(configDir, normServer, keyLine string) error {
	entries, err := loadKnownHosts(configDir)
	if err != nil {
		return err
	}
	replaced := false
	for i := range entries {
		if entries[i].server == normServer {
			entries[i].keyLine = keyLine
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, knownHostEntry{server: normServer, keyLine: keyLine})
	}
	return writeKnownHosts(configDir, entries)
}

// forgetKnownHost removes the entry for normServer, rewriting the cache. It
// returns removed=false when there was no matching entry (the caller decides
// how to report a no-op).
func forgetKnownHost(configDir, normServer string) (removed bool, err error) {
	entries, err := loadKnownHosts(configDir)
	if err != nil {
		return false, err
	}
	kept := entries[:0:0]
	for _, e := range entries {
		if e.server == normServer {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		return false, nil
	}
	if err := writeKnownHosts(configDir, kept); err != nil {
		return false, err
	}
	return true, nil
}

// tofuHostKeyCallback builds the trust-on-first-use host-key callback for a
// server whose normalized dial string is normServer, given the current cache
// entries. The returned *tofuResult is populated by the callback during the
// handshake; the caller reads it after a successful dial to know whether to
// record a first-use pin.
//
// Callback policy (spec 6.1):
//   - Reject any host key whose type is not Ed25519.
//   - Absent from cache (first use): capture the presented key + firstUse=true
//     and accept. It does NOT write the cache (that happens post-dial).
//   - Present and equal: accept.
//   - Present and different: return a changedHostKeyError carrying both
//     fingerprints, aborting the handshake. Never auto-overwrites.
func tofuHostKeyCallback(normServer string, entries []knownHostEntry) (gossh.HostKeyCallback, *tofuResult) {
	res := &tofuResult{}
	cb := func(_ string, _ net.Addr, key gossh.PublicKey) error {
		if key.Type() != gossh.KeyAlgoED25519 {
			return fmt.Errorf("server host key must be Ed25519, got %s", key.Type())
		}
		cached, ok := lookupKnownHost(entries, normServer)
		if !ok {
			res.firstUse = true
			res.key = key
			return nil
		}
		cachedKey, err := parseKeyLine(cached.keyLine)
		if err != nil {
			return usagef("cached host key for %s is unparseable: %v", normServer, err)
		}
		if bytes.Equal(cachedKey.Marshal(), key.Marshal()) {
			return nil
		}
		return &changedHostKeyError{
			server:      normServer,
			cachedFP:    fingerprintSHA256(cachedKey),
			presentedFP: fingerprintSHA256(key),
		}
	}
	return cb, res
}

// hostKeyLine renders a public key as a trimmed authorized_keys-style line for
// storage in the TOFU cache.
func hostKeyLine(key gossh.PublicKey) string {
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))
}
