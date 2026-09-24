package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// appDir is the per-user subdirectory under the config base directory. It
// mirrors keystore's appDir ("obscura") so the config file lives alongside the
// seed at <configDir>/obscura/. This is duplicated (not imported) because
// keystore does not export it and this module must not modify internal/.
const appDir = "obscura"

// configFileName is the optional hand-edited config file within appDir. Its
// absence is not an error.
const configFileName = "config.toml"

// Config config keys. Only these keys are recognized; any other key is a hard
// error so typos are caught rather than silently ignored.
const (
	configKeyServer  = "server"
	configKeyHostKey = "host_key"
)

// configPath returns the full path to the optional config file for a resolved
// config base directory: <configDir>/obscura/config.toml.
func configPath(configDir string) string {
	return filepath.Join(configDir, appDir, configFileName)
}

// fileConfig holds the values parsed from the config file. Empty strings mean
// the key was absent.
type fileConfig struct {
	server  string
	hostKey string
}

// loadConfig reads and parses <configDir>/obscura/config.toml. A missing file
// is not an error: it returns a zero fileConfig and found=false. A malformed
// file or an unknown key is an actionable usage error naming the path and key
// (the file is hand-edited).
func loadConfig(configDir string) (cfg fileConfig, found bool, err error) {
	path := configPath(configDir)
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return fileConfig{}, false, nil
		}
		return fileConfig{}, false, usagef("read config %s: %v", path, rerr)
	}
	cfg, err = parseConfig(path, data)
	if err != nil {
		return fileConfig{}, false, err
	}
	return cfg, true, nil
}

// parseConfig applies the strict line-based reader to data. It supports blank
// lines, '#' comments, and 'key = value' with optional surrounding whitespace
// and optional double-quotes around the value. Unknown keys and malformed lines
// are usage errors that name the file (path) and the offending line.
func parseConfig(path string, data []byte) (fileConfig, error) {
	var cfg fileConfig
	sc := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return fileConfig{}, usagef("config %s line %d: expected 'key = value', got %q", path, lineNo, raw)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			return fileConfig{}, usagef("config %s line %d: missing key before '=': %q", path, lineNo, raw)
		}
		val, err := unquoteValue(val)
		if err != nil {
			return fileConfig{}, usagef("config %s line %d: %v", path, lineNo, err)
		}
		switch key {
		case configKeyServer:
			cfg.server = val
		case configKeyHostKey:
			cfg.hostKey = val
		default:
			return fileConfig{}, usagef("config %s line %d: unknown key %q (known keys: %s, %s)",
				path, lineNo, key, configKeyServer, configKeyHostKey)
		}
	}
	if err := sc.Err(); err != nil {
		return fileConfig{}, usagef("read config %s: %v", path, err)
	}
	return cfg, nil
}

// unquoteValue strips a single pair of surrounding double-quotes from a value
// if present, returning the inner text verbatim. A value that opens a quote but
// does not close it is an error. Unquoted values are returned as-is (already
// trimmed by the caller).
func unquoteValue(val string) (string, error) {
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		// Fully double-quoted: decode with Go string rules so it round-trips
		// with renderConfig's %q quoting (handles embedded quotes/backslashes).
		unquoted, err := strconv.Unquote(val)
		if err != nil {
			return "", fmt.Errorf("invalid quoted value: %w", err)
		}
		return unquoted, nil
	}
	if strings.HasPrefix(val, "\"") || strings.HasSuffix(val, "\"") {
		return "", fmt.Errorf("unbalanced double-quote in value")
	}
	return val, nil
}

// writeConfigValue creates or updates the config file at
// <configDir>/obscura/config.toml, setting key to value. The directory is
// created 0700 and the file written 0600 via an atomic temp+rename. Existing
// recognized keys are preserved; unrecognized keys already present are rejected
// (the file must be valid before it can be edited). Comments and blank lines are
// NOT preserved: the file is rewritten with only the known keys in a stable
// order. This is documented behavior for `obscura config set`.
func writeConfigValue(configDir, key, value string) (string, error) {
	if key != configKeyServer && key != configKeyHostKey {
		return "", usagef("unknown config key %q (known keys: %s, %s)", key, configKeyServer, configKeyHostKey)
	}

	dir := filepath.Join(configDir, appDir)
	path := filepath.Join(dir, configFileName)

	// Start from the existing config so other known keys are preserved. A
	// malformed existing file is a hard error rather than a silent overwrite.
	cfg, _, err := loadConfig(configDir)
	if err != nil {
		return "", err
	}
	switch key {
	case configKeyServer:
		cfg.server = value
	case configKeyHostKey:
		cfg.hostKey = value
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	content := renderConfig(cfg)
	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// renderConfig serializes the known keys in a stable order, quoting values.
// Empty values are omitted so the file only lists keys the user has set.
func renderConfig(cfg fileConfig) string {
	pairs := map[string]string{}
	if cfg.server != "" {
		pairs[configKeyServer] = cfg.server
	}
	if cfg.hostKey != "" {
		pairs[configKeyHostKey] = cfg.hostKey
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# obscura config (managed by 'obscura config set')\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %q\n", k, pairs[k])
	}
	return b.String()
}

// writeFileAtomic writes data to path via a temp file in the same directory
// followed by a rename, so a concurrent reader never sees a partial file. The
// temp file is created with the target perm and cleaned up on failure.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp config: %w", err)
	}
	return nil
}
