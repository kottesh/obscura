package sshclient

import (
	"testing"
	"time"
)

// TestParseListingRow parses captured sample rows in the exact format the
// server's writeListing emits (internal/sshsrv/handlers.go): tab-separated
// id, size, RFC3339-UTC created, direction, carrier, name, terminated by '\n'.
func TestParseListingRow(t *testing.T) {
	wantTime := time.Date(2024, 6, 1, 12, 30, 45, 0, time.UTC)

	tests := []struct {
		name    string
		input   string
		want    []ListRow
		wantErr bool
	}{
		{
			name:  "single sent row with name",
			input: "abc123DEF456ghij\t2048\t2024-06-01T12:30:45Z\tsent\tpackage\tdoc.pkg\n",
			want: []ListRow{{
				ID:        "abc123DEF456ghij",
				Size:      2048,
				CreatedAt: wantTime,
				Direction: "sent",
				Carrier:   "package",
				Name:      "doc.pkg",
			}},
		},
		{
			name:  "received row with empty name",
			input: "ZZZ0000000000000\t0\t2024-06-01T12:30:45Z\trecv\tpng\t\n",
			want: []ListRow{{
				ID:        "ZZZ0000000000000",
				Size:      0,
				CreatedAt: wantTime,
				Direction: "recv",
				Carrier:   "png",
				Name:      "",
			}},
		},
		{
			name: "two rows",
			input: "id00000000000001\t10\t2024-06-01T12:30:45Z\tsent\tpackage\ta\n" +
				"id00000000000002\t20\t2024-06-01T12:30:45Z\trecv\tpng\tb\n",
			want: []ListRow{
				{ID: "id00000000000001", Size: 10, CreatedAt: wantTime, Direction: "sent", Carrier: "package", Name: "a"},
				{ID: "id00000000000002", Size: 20, CreatedAt: wantTime, Direction: "recv", Carrier: "png", Name: "b"},
			},
		},
		{
			name:  "empty listing",
			input: "",
			want:  []ListRow{},
		},
		{
			name:    "too few columns",
			input:   "id\t10\t2024-06-01T12:30:45Z\tsent\n",
			wantErr: true,
		},
		{
			name:    "non-numeric size",
			input:   "id00000000000001\tnope\t2024-06-01T12:30:45Z\tsent\tpackage\ta\n",
			wantErr: true,
		},
		{
			name:    "bad timestamp",
			input:   "id00000000000001\t10\tnot-a-time\tsent\tpackage\ta\n",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseListing([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseListing(%q) = %v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseListing(%q) error: %v", tc.input, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("row %d: got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestBuildUploadCommand checks flag assembly for the upload command surface.
func TestBuildUploadCommand(t *testing.T) {
	tests := []struct {
		name    string
		to      string
		display string
		carrier string
		want    string
	}{
		{name: "to only", to: "addr", want: "-to addr"},
		{name: "to and name", to: "addr", display: "doc.pkg", want: "-to addr -name doc.pkg"},
		{name: "to and carrier", to: "addr", carrier: "png", want: "-to addr -carrier png"},
		{name: "all", to: "addr", display: "n", carrier: "package", want: "-to addr -name n -carrier package"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildUploadCommand(tc.to, tc.display, tc.carrier); got != tc.want {
				t.Errorf("buildUploadCommand = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildListCommand checks the filter-to-command mapping and rejection of
// unknown filters.
func TestBuildListCommand(t *testing.T) {
	tests := []struct {
		filter  string
		want    string
		wantErr bool
	}{
		{filter: "", want: "list"},
		{filter: "sent", want: "list -sent"},
		{filter: "received", want: "list -received"},
		{filter: "bogus", wantErr: true},
	}
	for _, tc := range tests {
		t.Run("filter="+tc.filter, func(t *testing.T) {
			got, err := buildListCommand(tc.filter)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("buildListCommand(%q) = %q, want error", tc.filter, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildListCommand(%q) error: %v", tc.filter, err)
			}
			if got != tc.want {
				t.Errorf("buildListCommand(%q) = %q, want %q", tc.filter, got, tc.want)
			}
		})
	}
}

// TestMapExit checks the exit-status-to-typed-error mapping.
func TestMapExit(t *testing.T) {
	if err := mapExit(exitNotFound, "file not found\n"); err != ErrNotFound {
		t.Errorf("exitNotFound -> %v, want ErrNotFound", err)
	}
	if err := mapExit(exitTooLarge, "file too large\n"); err != ErrTooLarge {
		t.Errorf("exitTooLarge -> %v, want ErrTooLarge", err)
	}
	err := mapExit(exitInvalid, "invalid arguments\n")
	var re *RemoteError
	if !asRemote(err, &re) {
		t.Fatalf("exitInvalid -> %T, want *RemoteError", err)
	}
	if re.ExitCode != exitInvalid || re.Stderr != "invalid arguments" {
		t.Errorf("RemoteError = %+v, want exit=%d stderr=%q", re, exitInvalid, "invalid arguments")
	}
}

func asRemote(err error, target **RemoteError) bool {
	if re, ok := err.(*RemoteError); ok {
		*target = re
		return true
	}
	return false
}
