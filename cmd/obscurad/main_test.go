package main

import "testing"

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(t *testing.T, c config)
	}{
		{
			name: "defaults",
			args: nil,
			check: func(t *testing.T, c config) {
				if c.addr != ":2222" || c.dbPath != "obscura.db" || c.hostKeyPath != "obscura_host_ed25519" {
					t.Fatalf("unexpected defaults: %+v", c)
				}
			},
		},
		{
			name: "all set",
			args: []string{"-addr", ":9000", "-host-key", "/tmp/hk", "-db", "/tmp/db.sqlite"},
			check: func(t *testing.T, c config) {
				if c.addr != ":9000" || c.hostKeyPath != "/tmp/hk" || c.dbPath != "/tmp/db.sqlite" {
					t.Fatalf("unexpected: %+v", c)
				}
			},
		},
		{name: "unknown flag", args: []string{"-nope"}, wantErr: true},
		{name: "unexpected positional", args: []string{"extra"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := parseFlags(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}

func TestEnsureHostKeyGeneratesAndReuses(t *testing.T) {
	path := t.TempDir() + "/hostkey"
	if err := ensureHostKey(path); err != nil {
		t.Fatalf("first ensureHostKey: %v", err)
	}
	// Second call must be a no-op (reuse), not regenerate/error.
	if err := ensureHostKey(path); err != nil {
		t.Fatalf("second ensureHostKey: %v", err)
	}
}
