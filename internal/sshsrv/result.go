package sshsrv

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/kottesh/obscura/internal/storage"
)

// Exit codes returned to the SSH client (spec 6.3). Zero is success; every
// failure path returns a stable non-zero code so clients can branch on it.
const (
	exitOK       = 0
	exitFailure  = 1
	exitInvalid  = 2
	exitNotFound = 3
	exitTooLarge = 4
	exitStorage  = 5
)

// Stable stderr messages (spec 6.3). notFoundMessage is shared by the missing
// and unauthorized paths so the two are indistinguishable.
const (
	notFoundMessage = "file not found"
	tooLargeMessage = "file too large"
	storageMessage  = "storage error"
)

// session abstracts the parts of ssh.Session the handlers use, so the handler
// logic is testable with in-memory buffers and no live network. The real
// ssh.Session satisfies this interface.
type session interface {
	io.Reader // stdin (encrypted upload bytes)
	io.Writer // stdout (file id, listing, or raw encrypted bytes)
	Stderr() io.Writer
	Exit(code int) error
}

// ctEq reports whether two 32-byte ids are equal in constant time, avoiding a
// timing side channel on identity comparisons (spec 11 authorization).
func ctEq(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// authorizedForDownload is the download/read authorization predicate (spec
// 6.2): the caller must be the owner or the receiver of the record.
func authorizedForDownload(caller [32]byte, rec *storage.FileRecord) bool {
	if rec == nil {
		return false
	}
	return ctEq(caller, rec.OwnerUserID) || ctEq(caller, rec.ReceiverUserID)
}

// exitNotFoundResult is the single centralized missing/unauthorized exit used by
// both download and delete so they emit an identical message and identical exit
// code (spec 6.2, 6.3). No other path may write notFoundMessage.
func exitNotFoundResult(s session) error {
	_, _ = fmt.Fprintln(s.Stderr(), notFoundMessage)
	return s.Exit(exitNotFound)
}

// exitInvalidResult reports an invalid-arguments failure (spec 6.3): concise
// stderr, nothing on stdout.
func exitInvalidResult(s session, msg string) error {
	_, _ = fmt.Fprintln(s.Stderr(), msg)
	return s.Exit(exitInvalid)
}

// exitStorageResult reports a storage failure with a generic message (spec 6.3)
// so internal details never leak to the client.
func exitStorageResult(s session) error {
	_, _ = fmt.Fprintln(s.Stderr(), storageMessage)
	return s.Exit(exitStorage)
}
