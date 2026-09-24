package sshclient

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// listTimeLayout is the timestamp format the server emits in a listing row. It
// must match internal/sshsrv.writeListing, which formats CreatedAt as UTC with
// this exact layout (spec 6.2 list).
const listTimeLayout = "2006-01-02T15:04:05Z"

// listColumns is the number of tab-separated fields per listing row emitted by
// the server: id, size, created, direction, carrier, name. The trailing name
// column may be empty but is always present.
const listColumns = 6

// ListRow is one parsed listing record (spec 6.2 list). It mirrors the columns
// the server writes: id, size, created timestamp, direction relative to the
// caller, carrier type, and an optional display name.
type ListRow struct {
	// ID is the server file id.
	ID string
	// Size is the encrypted content size in bytes.
	Size uint64
	// CreatedAt is the record creation time (UTC).
	CreatedAt time.Time
	// Direction is "sent" when the caller owns the record or "recv" when the
	// caller is the receiver, matching the server's rendering.
	Direction string
	// Carrier is the carrier type ("package" or "png").
	Carrier string
	// Name is the optional sender-supplied display name; it may be empty.
	Name string
}

// ParseListing parses the server's listing output into rows. The server writes
// one tab-separated row per record terminated by '\n':
//
//	id \t size \t created(RFC3339 UTC) \t direction \t carrier \t name \n
//
// The name field may be empty and is the last column. Trailing empty lines
// (e.g. from an empty listing) yield no rows. Any malformed row is a hard
// error so the CLI never renders a half-parsed listing.
func ParseListing(out []byte) ([]ListRow, error) {
	text := string(out)
	// Split on newlines; the server terminates every row with '\n', so the
	// final split element is an empty string we skip.
	lines := strings.Split(text, "\n")
	rows := make([]ListRow, 0, len(lines))
	for i, line := range lines {
		if line == "" {
			continue
		}
		row, err := parseListRow(line)
		if err != nil {
			return nil, fmt.Errorf("sshclient: listing line %d: %w", i+1, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// parseListRow parses a single tab-separated listing line. It requires exactly
// listColumns fields; splitting with SplitN keeps a name that contained no
// tabs intact (names are control-character free but the parser does not depend
// on that beyond field count).
func parseListRow(line string) (ListRow, error) {
	// The name is the final column and cannot contain a tab (the server
	// sanitizes it), so a plain split on tab yields exactly listColumns fields.
	fields := strings.Split(line, "\t")
	if len(fields) != listColumns {
		return ListRow{}, fmt.Errorf("expected %d tab-separated fields, got %d", listColumns, len(fields))
	}

	size, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return ListRow{}, fmt.Errorf("invalid size %q: %w", fields[1], err)
	}

	created, err := time.Parse(listTimeLayout, fields[2])
	if err != nil {
		return ListRow{}, fmt.Errorf("invalid timestamp %q: %w", fields[2], err)
	}

	return ListRow{
		ID:        fields[0],
		Size:      size,
		CreatedAt: created,
		Direction: fields[3],
		Carrier:   fields[4],
		Name:      fields[5],
	}, nil
}
