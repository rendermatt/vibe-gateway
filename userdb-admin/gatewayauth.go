package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// dummyHash is compared against when the username doesn't exist, so a miss costs
// the same as a wrong password. Without it, response time leaks which usernames
// are real. Generated once at cost 12 for a value nobody knows.
const dummyHash = "$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// credCache memoises successful gateway-user verifications.
//
// This sits on the gateway's hot path: without it every single proxied request
// pays a full bcrypt verify (~250ms at cost 12) plus a database round trip.
// Only successes are cached, so a brute-forcer still pays full cost per attempt
// and the cache can't be used to keep a revoked password alive beyond its TTL.
type credCache struct {
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	items map[[32]byte]time.Time
}

func newCredCache(ttl time.Duration) *credCache {
	return &credCache{ttl: ttl, now: time.Now, items: make(map[[32]byte]time.Time)}
}

func credKey(user, pass string) [32]byte {
	return sha256.Sum256([]byte(user + "\x00" + pass))
}

func (c *credCache) get(k [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.items[k]
	if !ok {
		return false
	}
	if c.now().After(exp) {
		delete(c.items, k)
		return false
	}
	return true
}

func (c *credCache) put(k [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) > 1024 {
		c.items = make(map[[32]byte]time.Time)
	}
	c.items[k] = c.now().Add(c.ttl)
}

// invalidate drops the whole cache. Called after any password change or delete
// so a revoked credential stops working immediately rather than at TTL expiry.
func (c *credCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[[32]byte]time.Time)
}

// handleGatewayAuth is the forward_auth endpoint. Caddy proxies a copy of every
// gateway request here; 2xx lets it through, anything else is returned to the
// client verbatim.
//
// It is deliberately NOT behind the admin basic-auth middleware -- the gateway
// presents the end user's credentials, not the admin's. The shared token is what
// keeps it from being an open password oracle: userdb-admin is a public service,
// so without it anyone could brute-force gateway credentials here and bypass the
// gateway's own IP allow list.
func (s *server) handleGatewayAuth(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Gateway-Token")), []byte(s.cfg.gatewayToken)) != 1 {
		s.log.Warn("gateway auth called with a bad or missing token",
			"remote", r.RemoteAddr, "uri", r.Header.Get("X-Forwarded-Uri"))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		s.challenge(w)
		return
	}

	key := credKey(user, pass)
	if s.creds.get(key) {
		w.Header().Set("X-Auth-User", user)
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	hash, err := s.store.Lookup(ctx, user)
	switch {
	case errors.Is(err, ErrNotFound):
		// Spend the same time as a real verify so misses aren't distinguishable.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(pass))
		s.log.Info("gateway auth denied", "user", user, "reason", "no such user",
			"uri", r.Header.Get("X-Forwarded-Uri"))
		s.challenge(w)
		return
	case err != nil:
		// Fail closed, but say so distinctly: a database outage is not a bad
		// password, and conflating them makes the failure impossible to debug.
		s.log.Error("gateway auth could not reach the database", "err", err)
		http.Error(w, "auth backend unavailable", http.StatusServiceUnavailable)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
		s.log.Info("gateway auth denied", "user", user, "reason", "wrong password",
			"uri", r.Header.Get("X-Forwarded-Uri"))
		s.challenge(w)
		return
	}

	s.creds.put(key)
	w.Header().Set("X-Auth-User", user)
	w.WriteHeader(http.StatusOK)
}

func (s *server) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="vibe-gateway", charset="UTF-8"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
