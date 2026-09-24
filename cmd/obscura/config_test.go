package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfigFile writes content to <configDir>/obscura/config.toml, creating
// the app subdirectory. All paths are under t.TempDir().
func writeConfigFile(t *testing.T, configDir, content string) string {
	t.Helper()
	dir := filepath.Join(configDir, appDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestParseConfig covers valid files (quoted/unquoted, comments, blank lines),
// unknown keys, and malformed lines.
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantServer  string
		wantHostKey string
		wantErr     string // substring; "" means no error
	}{
		{
			name: "valid mixed quoting comments blanks",
			content: "# a comment\n\n" +
				"server = \"host.example:2222\"\n" +
				"  host_key = ssh-ed25519 AAAA...   \n" +
				"\n# trailing comment\n",
			wantServer:  "host.example:2222",
			wantHostKey: "ssh-ed25519 AAAA...",
		},
		{
			name:        "unquoted server",
			content:     "server = plainhost:1234\n",
			wantServer:  "plainhost:1234",
			wantHostKey: "",
		},
		{
			name:    "unknown key names the key",
			content: "srever = x\n",
			wantErr: `unknown key "srever"`,
		},
		{
			name:    "malformed line no equals",
			content: "server host:port\n",
			wantErr: "expected 'key = value'",
		},
		{
			name:    "unbalanced quote",
			content: "server = \"host:port\n",
			wantErr: "unbalanced double-quote",
		},
		{
			name:    "empty key",
			content: " = value\n",
			wantErr: "missing key",
		},
		{
			name:        "empty file",
			content:     "",
			wantServer:  "",
			wantHostKey: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfig("/tmp/obscura/config.toml", []byte(tc.content))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				if !strings.Contains(err.Error(), "/tmp/obscura/config.toml") {
					t.Errorf("error %q should name the file path", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.server != tc.wantServer {
				t.Errorf("server = %q, want %q", cfg.server, tc.wantServer)
			}
			if cfg.hostKey != tc.wantHostKey {
				t.Errorf("host_key = %q, want %q", cfg.hostKey, tc.wantHostKey)
			}
		})
	}
}

// TestLoadConfigAbsentIsNotError verifies a missing config file yields no error
// and empty values.
func TestLoadConfigAbsentIsNotError(t *testing.T) {
	dir := t.TempDir()
	cfg, found, err := loadConfig(dir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if found {
		t.Error("found should be false for absent file")
	}
	if cfg.server != "" || cfg.hostKey != "" {
		t.Errorf("absent config should be empty, got %+v", cfg)
	}
}

// TestParseGlobalServerPrecedence checks flag > env > file > default for server.
func TestParseGlobalServerPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		fileServer string
		envServer  string
		flagServer string // "" means no --server flag
		want       string
	}{
		{name: "flag wins over env and file", fileServer: "A", envServer: "C", flagServer: "B", want: "B"},
		{name: "env wins over file", fileServer: "A", envServer: "C", flagServer: "", want: "C"},
		{name: "file used when no flag/env", fileServer: "A", envServer: "", flagServer: "", want: "A"},
		{name: "none configured stays empty", fileServer: "", envServer: "", flagServer: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.fileServer != "" {
				writeConfigFile(t, dir, "server = "+tc.fileServer+"\n")
			}
			env := map[string]string{}
			if tc.envServer != "" {
				env[envServer] = tc.envServer
			}
			getenv := func(k string) string { return env[k] }

			args := []string{"--config-dir", dir}
			if tc.flagServer != "" {
				args = append(args, "--server", tc.flagServer)
			}
			args = append(args, "address")

			g, _, err := parseGlobal(args, getenv)
			if err != nil {
				t.Fatalf("parseGlobal: %v", err)
			}
			if g.server != tc.want {
				t.Errorf("server = %q, want %q", g.server, tc.want)
			}
		})
	}
}

// TestParseGlobalHostKeyPrecedence checks flag > env > file > default for
// host_key.
func TestParseGlobalHostKeyPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		fileHostKey string
		envHostKey  string
		flagHostKey string
		want        string
	}{
		{name: "flag wins", fileHostKey: "A", envHostKey: "C", flagHostKey: "B", want: "B"},
		{name: "env wins over file", fileHostKey: "A", envHostKey: "C", flagHostKey: "", want: "C"},
		{name: "file used when no flag/env", fileHostKey: "A", envHostKey: "", flagHostKey: "", want: "A"},
		{name: "none stays empty", fileHostKey: "", envHostKey: "", flagHostKey: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.fileHostKey != "" {
				writeConfigFile(t, dir, "host_key = "+tc.fileHostKey+"\n")
			}
			env := map[string]string{}
			if tc.envHostKey != "" {
				env[envHostKey] = tc.envHostKey
			}
			getenv := func(k string) string { return env[k] }

			args := []string{"--config-dir", dir}
			if tc.flagHostKey != "" {
				args = append(args, "--host-key", tc.flagHostKey)
			}
			args = append(args, "address")

			g, _, err := parseGlobal(args, getenv)
			if err != nil {
				t.Fatalf("parseGlobal: %v", err)
			}
			if g.hostKey != tc.want {
				t.Errorf("host_key = %q, want %q", g.hostKey, tc.want)
			}
		})
	}
}

// TestConfigDirResolution checks --config-dir flag > OBSCURA_CONFIG_DIR env, and
// that config.toml is loaded from the resolved dir's obscura/ subdir.
func TestConfigDirResolution(t *testing.T) {
	flagDir := t.TempDir()
	envDir := t.TempDir()
	writeConfigFile(t, flagDir, "server = from-flag-dir\n")
	writeConfigFile(t, envDir, "server = from-env-dir\n")

	getenv := func(k string) string {
		if k == envConfigDir {
			return envDir
		}
		return ""
	}

	// Flag wins over env for config-dir; config loaded from flagDir.
	g, _, err := parseGlobal([]string{"--config-dir", flagDir, "address"}, getenv)
	if err != nil {
		t.Fatalf("parseGlobal: %v", err)
	}
	if g.configDir != flagDir {
		t.Errorf("configDir = %q, want %q", g.configDir, flagDir)
	}
	if g.server != "from-flag-dir" {
		t.Errorf("server = %q, want from-flag-dir", g.server)
	}

	// No flag: env dir wins; config loaded from envDir.
	g2, _, err := parseGlobal([]string{"address"}, getenv)
	if err != nil {
		t.Fatalf("parseGlobal (env dir): %v", err)
	}
	if g2.configDir != envDir {
		t.Errorf("configDir = %q, want %q", g2.configDir, envDir)
	}
	if g2.server != "from-env-dir" {
		t.Errorf("server = %q, want from-env-dir", g2.server)
	}
}

// TestParseGlobalMalformedConfigIsUsageError verifies a malformed config file
// surfaces as an actionable usage error naming the path.
func TestParseGlobalMalformedConfigIsUsageError(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "bogus line without equals\n")
	getenv := func(string) string { return "" }

	_, _, err := parseGlobal([]string{"--config-dir", dir, "address"}, getenv)
	if err == nil {
		t.Fatal("expected error for malformed config")
	}
	if !isUsageError(err) {
		t.Errorf("expected usage error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q should name the config path %q", err.Error(), path)
	}
}

// TestRequireServerMentionsConfig verifies the no-server error names the config
// file.
func TestRequireServerMentionsConfig(t *testing.T) {
	dir := t.TempDir()
	g := globalFlags{configDir: dir}
	_, err := g.requireServer()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "config.toml") {
		t.Errorf("error %q should mention config.toml", err.Error())
	}
}

// TestWriteConfigValueRoundTrip verifies config set creates the file with the
// right perms and that a subsequent load round-trips the value.
func TestWriteConfigValueRoundTrip(t *testing.T) {
	dir := t.TempDir()

	path, err := writeConfigValue(dir, configKeyServer, "host:2222")
	if err != nil {
		t.Fatalf("writeConfigValue: %v", err)
	}

	// File perm 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file perm = %v, want 0600", fi.Mode().Perm())
	}
	// Dir perm 0700.
	di, err := os.Stat(filepath.Join(dir, appDir))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %v, want 0700", di.Mode().Perm())
	}

	// Round-trip: server loads back, then set host_key preserves server.
	cfg, found, err := loadConfig(dir)
	if err != nil || !found {
		t.Fatalf("loadConfig: found=%v err=%v", found, err)
	}
	if cfg.server != "host:2222" {
		t.Errorf("server = %q, want host:2222", cfg.server)
	}

	if _, err := writeConfigValue(dir, configKeyHostKey, "ssh-ed25519 AAAA"); err != nil {
		t.Fatalf("writeConfigValue host_key: %v", err)
	}
	cfg2, _, err := loadConfig(dir)
	if err != nil {
		t.Fatalf("loadConfig 2: %v", err)
	}
	if cfg2.server != "host:2222" {
		t.Errorf("server not preserved after setting host_key: %q", cfg2.server)
	}
	if cfg2.hostKey != "ssh-ed25519 AAAA" {
		t.Errorf("host_key = %q, want ssh-ed25519 AAAA", cfg2.hostKey)
	}
}

// TestWriteConfigValueSpecialCharsRoundTrip verifies that values containing
// double-quotes and backslashes survive a write+reload unchanged (renderConfig
// %q must round-trip with unquoteValue's strconv.Unquote).
func TestWriteConfigValueSpecialCharsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, val := range []string{`a"b`, `c\d`, `quote"and\back`, `trailing\`} {
		if _, err := writeConfigValue(dir, configKeyServer, val); err != nil {
			t.Fatalf("writeConfigValue(%q): %v", val, err)
		}
		cfg, found, err := loadConfig(dir)
		if err != nil || !found {
			t.Fatalf("loadConfig(%q): found=%v err=%v", val, found, err)
		}
		if cfg.server != val {
			t.Errorf("round-trip %q -> %q", val, cfg.server)
		}
	}
}

// TestWriteConfigValueUnknownKey verifies set rejects unknown keys.
func TestWriteConfigValueUnknownKey(t *testing.T) {
	dir := t.TempDir()
	_, err := writeConfigValue(dir, "nope", "x")
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "unknown config key") {
		t.Errorf("error %q should mention unknown config key", err.Error())
	}
}

// runConfigCLI invokes run() for the config command with a custom env map so
// tests exercise the real dispatch and stream discipline.
func runConfigCLI(t *testing.T, env map[string]string, args ...string) cliResult {
	t.Helper()
	getenv := func(k string) string { return env[k] }
	var out, errb bytes.Buffer
	code := run(context.Background(), args, bytes.NewReader(nil), &out, &errb, getenv)
	return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
}

// TestConfigCommandShowAndSet exercises the config subcommand end to end: an
// initial show reports (unset), 'config set' writes the file, and a subsequent
// show reflects the value. JSON mode emits exactly one object.
func TestConfigCommandShowAndSet(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{}

	// Show with nothing configured: server/host_key unset, on stdout.
	show := runConfigCLI(t, env, "--config-dir", dir, "config")
	if show.code != exitOK {
		t.Fatalf("config show exit=%d stderr=%s", show.code, show.stderr)
	}
	if !strings.Contains(show.stdout, "server: (unset)") {
		t.Errorf("show stdout should mark server unset: %q", show.stdout)
	}
	if !strings.Contains(show.stdout, configPath(dir)) {
		t.Errorf("show stdout should include config path: %q", show.stdout)
	}

	// Set server.
	set := runConfigCLI(t, env, "--config-dir", dir, "config", "set", "server", "host:2222")
	if set.code != exitOK {
		t.Fatalf("config set exit=%d stderr=%s", set.code, set.stderr)
	}

	// Show again reflects the file value with source "config file".
	show2 := runConfigCLI(t, env, "--config-dir", dir, "config")
	if show2.code != exitOK {
		t.Fatalf("config show2 exit=%d stderr=%s", show2.code, show2.stderr)
	}
	if !strings.Contains(show2.stdout, "server: host:2222 (config file)") {
		t.Errorf("show2 stdout should reflect file server: %q", show2.stdout)
	}

	// JSON mode: exactly one object on stdout.
	js := runConfigCLI(t, env, "--json", "--config-dir", dir, "config")
	if js.code != exitOK {
		t.Fatalf("config json exit=%d stderr=%s", js.code, js.stderr)
	}
	if ansiPattern.MatchString(js.stdout) {
		t.Errorf("config json stdout has ANSI escapes")
	}
	dec := json.NewDecoder(strings.NewReader(js.stdout))
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("config json not one object: %v (%q)", err, js.stdout)
	}
	if dec.More() {
		t.Error("config json stdout has more than one value")
	}
	if obj["server"] != "host:2222" {
		t.Errorf("json server = %v, want host:2222", obj["server"])
	}
	if obj["server_source"] != "config file" {
		t.Errorf("json server_source = %v, want config file", obj["server_source"])
	}
}

// TestConfigSetUnknownKeyCLI verifies 'config set <bad>' exits with a usage
// error to stderr and empty stdout.
func TestConfigSetUnknownKeyCLI(t *testing.T) {
	dir := t.TempDir()
	res := runConfigCLI(t, map[string]string{}, "--config-dir", dir, "config", "set", "bogus", "x")
	if res.code != exitUsage {
		t.Fatalf("expected usage exit, got %d stderr=%s", res.code, res.stderr)
	}
	if res.stdout != "" {
		t.Errorf("config set error stdout must be empty, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "unknown config key") {
		t.Errorf("stderr should mention unknown config key: %q", res.stderr)
	}
}

// TestConfigShowEnvSource verifies the effective-config report attributes an
// env-provided server to the environment source.
func TestConfigShowEnvSource(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{envServer: "env-host:9999"}
	res := runConfigCLI(t, env, "--config-dir", dir, "config")
	if res.code != exitOK {
		t.Fatalf("config show exit=%d stderr=%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "server: env-host:9999 (environment)") {
		t.Errorf("show stdout should attribute env source: %q", res.stdout)
	}
}
