package sshsrv

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kottesh/obscura/internal/storage"
)

// filePrefix is the reserved SSH login username prefix that routes a session to
// file-request handling (download or delete) rather than upload/list (spec 6.1).
const filePrefix = "f:"

// fileIDLength and fileIDAlphabet replicate storage.NewID's id parameters. The
// storage package keeps these unexported, so they are duplicated here to
// validate an f:<id> remainder BEFORE touching storage. TestFileIDValidator
// asserts a real storage.NewID() output passes this validator, guarding against
// drift between the two definitions.
const (
	fileIDLength   = 16
	fileIDAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
)

// route is the classification of an SSH session into one of the three top-level
// operations (spec 6.2 dispatcher).
type route int

const (
	// routeFile is an f:<id> session: download (no command) or delete (rm).
	routeFile route = iota
	// routeList is a `list` session.
	routeList
	// routeUpload is a normal session: upload stdin.
	routeUpload
)

// dispatch is the pure routing decision (spec 6.2). First match wins:
//
//	user starts with "f:"  -> file request, id = user[2:]
//	command[0] == "list"   -> list
//	otherwise              -> upload
//
// An empty id ("f:") still routes to file handling; it must not fall through to
// upload. fileID is only meaningful when the returned route is routeFile.
func dispatch(user string, command []string) (r route, fileID string) {
	if strings.HasPrefix(user, filePrefix) {
		return routeFile, user[len(filePrefix):]
	}
	if len(command) > 0 && command[0] == "list" {
		return routeList, ""
	}
	return routeUpload, ""
}

// validFileID reports whether id is exactly fileIDLength characters drawn from
// fileIDAlphabet. A malformed id must be treated as not-found by callers, never
// as a distinct error (spec 6.2).
func validFileID(id string) bool {
	if len(id) != fileIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(fileIDAlphabet, rune(id[i])) {
			return false
		}
	}
	return true
}

// fileAction is the operation requested by an f:<id> session.
type fileAction int

const (
	// actionDownload streams encrypted content to stdout (empty command).
	actionDownload fileAction = iota
	// actionDelete removes an owned record (command == ["rm"]).
	actionDelete
)

// errInvalidArgs signals an invalid-arguments condition (spec 6.3): non-zero
// exit with a concise stderr message and nothing read or streamed.
var errInvalidArgs = errors.New("invalid arguments")

// parseFileCommand validates the command surface of an f:<id> session. Only an
// empty command (download) or exactly ["rm"] (delete) is accepted; anything
// else is invalid arguments (spec 6.2).
func parseFileCommand(command []string) (fileAction, error) {
	switch {
	case len(command) == 0:
		return actionDownload, nil
	case len(command) == 1 && command[0] == "rm":
		return actionDelete, nil
	default:
		return 0, errInvalidArgs
	}
}

// uploadArgs is the validated result of parsing upload flags.
type uploadArgs struct {
	// to is the required receiver address string, validated by DecodeAddress.
	to string
	// name is the optional, sanitized display name (<= maxNameBytes).
	name string
	// carrier is the validated carrier type (package or png).
	carrier storage.CarrierType
}

// maxNameBytes bounds the display name to keep it as small metadata and to
// limit terminal-injection surface in a receiver's list (spec 3.1, 5).
const maxNameBytes = 255

// parseUploadArgs validates upload flags BEFORE any body is read (spec 11). It
// accepts only -to (required), -name (optional), and -carrier (optional,
// package|png). Unknown flags (including a -to typo) are invalid arguments so a
// malformed command never silently uploads. -to is validated solely by the
// caller via identity.DecodeAddress; this function only extracts the string.
func parseUploadArgs(args []string) (uploadArgs, error) {
	var (
		out         uploadArgs
		haveTo      bool
		haveName    bool
		haveCarrier bool
	)
	out.carrier = storage.PackageCarrier

	i := 0
	for i < len(args) {
		arg := args[i]
		// Support both "-flag value" and "-flag=value" forms.
		var (
			flag  string
			value string
			inKV  bool
		)
		if eq := strings.IndexByte(arg, '='); eq >= 0 && strings.HasPrefix(arg, "-") {
			flag = arg[:eq]
			value = arg[eq+1:]
			inKV = true
		} else {
			flag = arg
		}

		switch flag {
		case "-to":
			if !inKV {
				if i+1 >= len(args) {
					return uploadArgs{}, errInvalidArgs
				}
				value = args[i+1]
				i++
			}
			if haveTo {
				return uploadArgs{}, errInvalidArgs
			}
			out.to = value
			haveTo = true
		case "-name":
			if !inKV {
				if i+1 >= len(args) {
					return uploadArgs{}, errInvalidArgs
				}
				value = args[i+1]
				i++
			}
			if haveName {
				return uploadArgs{}, errInvalidArgs
			}
			clean, err := sanitizeName(value)
			if err != nil {
				return uploadArgs{}, err
			}
			out.name = clean
			haveName = true
		case "-carrier":
			if !inKV {
				if i+1 >= len(args) {
					return uploadArgs{}, errInvalidArgs
				}
				value = args[i+1]
				i++
			}
			if haveCarrier {
				return uploadArgs{}, errInvalidArgs
			}
			ct := storage.CarrierType(value)
			if !ct.Valid() {
				return uploadArgs{}, errInvalidArgs
			}
			out.carrier = ct
			haveCarrier = true
		default:
			// Any unknown token (e.g. a "-too" typo or a bare positional)
			// fails as invalid arguments rather than being ignored.
			return uploadArgs{}, errInvalidArgs
		}
		i++
	}

	if !haveTo {
		return uploadArgs{}, errInvalidArgs
	}
	return out, nil
}

// sanitizeName bounds a display name to maxNameBytes and rejects it if it
// contains non-printable, ANSI/control, or Unicode format/bidi characters,
// which could inject escape sequences or spoof the rendered name in a
// receiver's terminal when listed (spec 5, 8.3). The name is metadata only and
// is never treated as a filesystem path.
func sanitizeName(name string) (string, error) {
	if len(name) > maxNameBytes {
		return "", fmt.Errorf("%w: name exceeds %d bytes", errInvalidArgs, maxNameBytes)
	}
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: name is not valid UTF-8", errInvalidArgs)
	}
	for _, r := range name {
		// Reject C0 controls (incl. ESC 0x1b, NUL, newline), DEL, and the C1
		// control range which drive ANSI terminal escape sequences.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return "", fmt.Errorf("%w: name contains control characters", errInvalidArgs)
		}
		// Reject Unicode format/bidi-override and other non-graphic runes
		// (e.g. U+202E RIGHT-TO-LEFT OVERRIDE, zero-width joiners) that can
		// spoof how the name renders in a terminal listing.
		if unicode.Is(unicode.Cf, r) || !unicode.IsGraphic(r) {
			return "", fmt.Errorf("%w: name contains disallowed formatting characters", errInvalidArgs)
		}
	}
	return name, nil
}
