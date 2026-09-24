package sshsrv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/kottesh/obscura/internal/identity"
	"github.com/kottesh/obscura/internal/storage"
)

// handleUpload parses upload flags, then streams a size-bounded stdin body into
// the store as one FileRecord (spec 6.2 upload). Arguments are validated BEFORE
// any body is read: a missing/invalid -to or an unknown flag fails as invalid
// arguments with nothing consumed. The owner id is the authenticated caller;
// the receiver id comes only from DecodeAddress(-to). Self-send is allowed.
func handleUpload(ctx context.Context, s session, store storage.FileStore, caller [32]byte, args []string, maxUpload int64) error {
	parsed, err := parseUploadArgs(args)
	if err != nil {
		return exitInvalidResult(s, err.Error())
	}

	// DecodeAddress is the sole validator of -to: it rejects bad base58 and any
	// decoded length other than 64 bytes. We do not re-check the length here.
	addr, err := identity.DecodeAddress(parsed.to)
	if err != nil {
		return exitInvalidResult(s, "invalid receiver address")
	}

	rec := &storage.FileRecord{
		OwnerUserID:    caller,
		ReceiverUserID: addr.UserID,
		DisplayName:    parsed.name,
		CarrierType:    parsed.carrier,
	}

	// Bound stdin to maxUpload+1 so the store can detect overflow without ever
	// buffering an oversized payload. storage.Create rolls back its transaction
	// on any read error or ErrTooLarge, so an oversized or interrupted upload
	// leaves no committed row.
	body := io.LimitReader(s, maxUpload+1)

	if err := store.Create(ctx, rec, body); err != nil {
		switch {
		case errors.Is(err, storage.ErrTooLarge):
			_, _ = fmt.Fprintln(s.Stderr(), tooLargeMessage)
			return s.Exit(exitTooLarge)
		default:
			return exitStorageResult(s)
		}
	}

	// Success metadata: the file id as UTF-8 text on stdout, exit 0.
	_, _ = fmt.Fprintln(s, rec.ID)
	return s.Exit(exitOK)
}

// handleFile handles an f:<id> session: download (empty command) or delete
// (["rm"]). A malformed id yields the SAME not-found result as a missing id and
// never falls through to upload. The auth check happens before any content is
// opened (spec 6.2 download, delete).
func handleFile(ctx context.Context, s session, store storage.FileStore, caller [32]byte, id string, command []string) error {
	action, err := parseFileCommand(command)
	if err != nil {
		return exitInvalidResult(s, err.Error())
	}

	// Validate the id shape before hitting storage; a malformed id is reported
	// as not-found, identical to a well-formed but missing id.
	if !validFileID(id) {
		return exitNotFoundResult(s)
	}

	switch action {
	case actionDelete:
		return handleDelete(ctx, s, store, caller, id)
	default:
		return handleDownload(ctx, s, store, caller, id)
	}
}

// handleDownload streams a record's encrypted content to stdout only after the
// authorization check passes. Missing and unauthorized ids take the SAME
// centralized not-found exit; content is never opened before the check.
func handleDownload(ctx context.Context, s session, store storage.FileStore, caller [32]byte, id string) error {
	rec, err := store.Find(ctx, id)
	authorized := err == nil && (ctEq(caller, rec.OwnerUserID) || ctEq(caller, rec.ReceiverUserID))
	if !authorized {
		// Both "not found" and "found but unauthorized" exit identically.
		// A genuine storage error (not ErrNotFound) is also folded here so the
		// caller cannot probe existence via error differences; but surface a
		// generic storage failure when Find failed for a non-NotFound reason.
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return exitStorageResult(s)
		}
		return exitNotFoundResult(s)
	}

	// Only now open content and stream raw bytes to stdout.
	content, err := store.OpenContent(ctx, id)
	if err != nil {
		return exitStorageResult(s)
	}
	defer func() { _ = content.Close() }()

	if _, err := io.Copy(s, content); err != nil {
		// The transport may have failed mid-stream; report a storage/generic
		// failure. Partial bytes may already be on the wire, but the exit code
		// signals failure to the client.
		return exitStorageResult(s)
	}
	return s.Exit(exitOK)
}

// handleDelete removes an owned record. Deletion is owner-only: a receiver or
// third party (and a missing id) all receive the same not-found result via the
// centralized exit (spec 6.2 delete).
func handleDelete(ctx context.Context, s session, store storage.FileStore, caller [32]byte, id string) error {
	err := store.Delete(ctx, id, caller)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return exitNotFoundResult(s)
		}
		return exitStorageResult(s)
	}
	return s.Exit(exitOK)
}

// handleList returns records where the caller is owner or receiver (spec 6.2
// list). `list` (default) merges both directions; `list -sent` returns owned
// records; `list -received` returns received records. Output is UTF-8 text on
// stdout; exit 0.
func handleList(ctx context.Context, s session, store storage.FileStore, caller [32]byte, args []string) error {
	mode, err := parseListArgs(args)
	if err != nil {
		return exitInvalidResult(s, err.Error())
	}

	var records []storage.FileRecord
	switch mode {
	case listSent:
		records, err = store.ListOwned(ctx, caller)
	case listReceived:
		records, err = store.ListReceived(ctx, caller)
	default:
		owned, e1 := store.ListOwned(ctx, caller)
		if e1 != nil {
			return exitStorageResult(s)
		}
		received, e2 := store.ListReceived(ctx, caller)
		if e2 != nil {
			return exitStorageResult(s)
		}
		records = append(owned, received...)
	}
	if err != nil {
		return exitStorageResult(s)
	}

	writeListing(s, caller, records)
	return s.Exit(exitOK)
}

// listMode selects which direction(s) a list request returns.
type listMode int

const (
	listDefault listMode = iota
	listSent
	listReceived
)

// parseListArgs validates the list command flags: at most one of -sent or
// -received; anything else is invalid arguments.
func parseListArgs(args []string) (listMode, error) {
	// args excludes the leading "list" token.
	if len(args) == 0 {
		return listDefault, nil
	}
	if len(args) > 1 {
		return 0, errInvalidArgs
	}
	switch args[0] {
	case "-sent":
		return listSent, nil
	case "-received":
		return listReceived, nil
	default:
		return 0, errInvalidArgs
	}
}

// writeListing renders one line per record: id, size, created timestamp,
// direction relative to the caller, carrier type, and optional name. The
// display name has already been sanitized at upload, so it carries no control
// characters here.
func writeListing(s session, caller [32]byte, records []storage.FileRecord) {
	var b strings.Builder
	for i := range records {
		rec := &records[i]
		direction := "recv"
		if ctEq(caller, rec.OwnerUserID) {
			direction = "sent"
		}
		b.WriteString(rec.ID)
		b.WriteByte('\t')
		b.WriteString(strconv.FormatUint(rec.Size, 10))
		b.WriteByte('\t')
		b.WriteString(rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"))
		b.WriteByte('\t')
		b.WriteString(direction)
		b.WriteByte('\t')
		b.WriteString(string(rec.CarrierType))
		b.WriteByte('\t')
		b.WriteString(rec.DisplayName)
		b.WriteByte('\n')
	}
	_, _ = io.WriteString(s, b.String())
}
