package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type ctxKey int

const ctxAdminUser ctxKey = 0

// authenticator does HTTP Basic against ADMIN_USER + ADMIN_PASSWORD_HASH.
//
// Basic auth rather than a session cookie: cookies would add CSRF state, a
// signing key to manage, and login/logout UI, for a single-operator tool behind
// an IP allow list. It also keeps `curl -u` working, which matters for the
// break-glass path when the UI itself is broken.
//
// The one real problem with naive basic auth is that bcrypt then runs on every
// request, including /app.js -- slow, and a trivial CPU-exhaustion vector for
// anyone inside the allow list. Successful verifications are therefore cached
// briefly. Failures are never cached, so a brute-forcer still pays full bcrypt
// cost per attempt; the cache is itself the rate limiter.
type authenticator struct {
	user     string
	passHash []byte
	ttl      time.Duration
	now      func() time.Time

	mu    sync.Mutex
	cache map[[32]byte]time.Time
}

func newAuthenticator(user, hash string) *authenticator {
	return &authenticator{
		user:     user,
		passHash: []byte(hash),
		ttl:      5 * time.Minute,
		now:      time.Now,
		cache:    make(map[[32]byte]time.Time),
	}
}

// digest hashes both sides first so the constant-time compare runs over
// fixed-length inputs and doesn't leak the length of ADMIN_USER.
func digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func (a *authenticator) check(user, pass string) bool {
	key := sha256.Sum256([]byte(user + "\x00" + pass))

	a.mu.Lock()
	exp, hit := a.cache[key]
	a.mu.Unlock()
	if hit && a.now().Before(exp) {
		return true // only successful pairs are ever inserted
	}

	// Always run both comparisons so a wrong username costs the same as a wrong
	// password: no user enumeration via timing.
	userOK := subtle.ConstantTimeCompare(digest(user), digest(a.user)) == 1
	passOK := bcrypt.CompareHashAndPassword(a.passHash, []byte(pass)) == nil
	if !(userOK && passOK) {
		return false
	}

	a.mu.Lock()
	if len(a.cache) > 128 {
		a.cache = make(map[[32]byte]time.Time)
	}
	a.cache[key] = a.now().Add(a.ttl)
	a.mu.Unlock()
	return true
}

func (a *authenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !a.check(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="userdb-admin", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxAdminUser, u)))
	})
}

func adminUserOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxAdminUser).(string); ok {
		return v
	}
	return "?"
}

// requireCSRFHeader guards the mutating endpoints. Browsers attach basic auth
// credentials to cross-origin requests automatically, so basic auth alone is not
// CSRF-proof. A custom request header can't be set by an HTML form and forces a
// CORS preflight that a cross-origin attacker can't satisfy.
func requireCSRFHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Userdb-Admin") != "1" {
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "missing X-Userdb-Admin: 1 header", Code: "csrf"})
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
			writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{Error: "Content-Type must be application/json", Code: "content_type"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isJSONContentType(ct string) bool {
	if i := indexByteStr(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	for len(ct) > 0 && ct[len(ct)-1] == ' ' {
		ct = ct[:len(ct)-1]
	}
	return ct == "application/json"
}

func indexByteStr(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}
