package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxUsernameLen = 64
	minPasswordLen = 12
	maxPasswordLen = 72 // bcrypt's hard limit; x/crypto errors above this
)

var (
	// ErrLastUser guards the lockout case: with no accounts left, the gateway
	// rejects every request and there is no way back in through the UI.
	ErrLastUser = errors.New("refusing to delete the last remaining user")
	ErrNotFound = errors.New("user not found")
	ErrExists   = errors.New("user already exists")
)

// validationError marks errors whose text is safe to show the user. Anything
// not marked is reported generically, so a driver error carrying the connection
// string can never reach a browser just because someone added a new sentinel.
type validationError struct{ error }

func (v validationError) Unwrap() error { return v.error }

func invalid(format string, args ...any) error {
	return validationError{fmt.Errorf(format, args...)}
}

func isValidationError(err error) bool {
	var ve validationError
	return errors.As(err, &ve)
}

// usernameRe is a strict allowlist. Credentials arrive over HTTP Basic, which
// constrains what a username can portably be, and a narrow charset keeps names
// copy-pasteable and greppable in logs.
var usernameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._@+-]{0,62}[A-Za-z0-9])?$`)

// validateUsername rejects, in order of how badly each fails:
//
//	:            RFC 7617 splits "user:pass" on the FIRST colon, so a username
//	             containing one can never authenticate. This is the only rule
//	             here that is a hard protocol constraint rather than hygiene.
//	non-ASCII    browsers disagree on how to encode non-ASCII credentials in an
//	             Authorization header, so such an account works in one browser
//	             and not another.
//	control      unusable, and a log-injection vector.
//	everything   anything outside A-Za-z0-9 . _ @ + - is rejected by allowlist,
//	else         and names must start and end alphanumeric.
func validateUsername(u string) error {
	if u == "" {
		return invalid("username is empty")
	}
	if len(u) > maxUsernameLen {
		return invalid("username is %d bytes, max %d", len(u), maxUsernameLen)
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c < 0x21 || c > 0x7e {
			return invalid("username contains byte 0x%02x at offset %d; only printable ASCII with no spaces is allowed", c, i)
		}
		if c == ':' {
			return invalid(`username contains ":", which HTTP Basic auth uses to separate user from password`)
		}
	}
	if !usernameRe.MatchString(u) {
		return invalid("username %q is invalid: use 1-%d characters from A-Z a-z 0-9 . _ @ + - and start and end with a letter or digit", u, maxUsernameLen)
	}
	return nil
}

func validatePassword(p string) error {
	if len(p) < minPasswordLen {
		return invalid("password must be at least %d bytes", minPasswordLen)
	}
	if len(p) > maxPasswordLen {
		return invalid("password must be at most %d bytes (bcrypt ignores anything beyond that)", maxPasswordLen)
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return invalid("password must be printable ASCII (browsers disagree on how to encode anything else in an Authorization header)")
		}
	}
	if strings.TrimSpace(p) != p {
		return invalid("password has leading or trailing whitespace")
	}
	return nil
}

// bcryptHashRe matches the modular-crypt bcrypt encoding: exactly 60 chars.
var bcryptHashRe = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

func validateHash(h string) error {
	if !bcryptHashRe.MatchString(h) {
		return fmt.Errorf("not a valid bcrypt modular-crypt hash: want $2[aby]$NN$ plus 53 chars (60 total), got %d chars", len(h))
	}
	return nil
}
