package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type server struct {
	cfg   config
	store *Store
	auth  *authenticator
	creds *credCache
	log   *slog.Logger
}

var errReadOnly = errors.New("service is in READ_ONLY mode")

type listResponse struct {
	Users    []User `json:"users"`
	ReadOnly bool   `json:"readOnly"`
}

type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body: " + err.Error(), Code: "invalid"})
		return false
	}
	return true
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed", Code: "method"})
		return false
	}
	return true
}

type userRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *server) hashPassword(pw string) (string, error) {
	if err := validatePassword(pw); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), s.cfg.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	if err := validateHash(string(h)); err != nil {
		return "", fmt.Errorf("generated hash failed validation: %w", err)
	}
	return string(h), nil
}

func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	users, err := s.store.List(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Only usernames and timestamps cross this boundary, never hashes.
	writeJSON(w, http.StatusOK, listResponse{Users: users, ReadOnly: s.cfg.readOnly})
}

func (s *server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !s.checkWritable(w, r) {
		return
	}
	var req userRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validateUsername(req.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	hash, err := s.hashPassword(req.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.store.Add(ctx, req.Username, hash); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("user added", "admin", adminUserOf(r), "user", req.Username)
	s.respondWithList(w, r)
}

func (s *server) handleResetUser(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !s.checkWritable(w, r) {
		return
	}
	var req userRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := validateUsername(req.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	hash, err := s.hashPassword(req.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.store.SetHash(ctx, req.Username, hash); err != nil {
		s.fail(w, r, err)
		return
	}
	// The old password must stop working now, not when its cache entry expires.
	s.creds.invalidate()
	s.log.Info("password reset", "admin", adminUserOf(r), "user", req.Username)
	s.respondWithList(w, r)
}

func (s *server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !s.checkWritable(w, r) {
		return
	}
	var req userRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Password != "" {
		s.fail(w, r, errors.New("delete does not take a password"))
		return
	}
	if err := validateUsername(req.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.store.Delete(ctx, req.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	s.creds.invalidate()
	s.log.Info("user deleted", "admin", adminUserOf(r), "user", req.Username)
	s.respondWithList(w, r)
}

func (s *server) checkWritable(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.readOnly {
		s.fail(w, r, errReadOnly)
		return false
	}
	return true
}

// respondWithList re-reads after a write so the client always renders committed
// state rather than what it hoped happened.
func (s *server) respondWithList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	users, err := s.store.List(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, listResponse{Users: users, ReadOnly: s.cfg.readOnly})
}

// fail maps internal errors to client-safe responses. Anything unrecognised is
// treated as a database problem and reported without its text, since driver
// errors can carry the connection string.
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	var code, msg string

	switch {
	case errors.Is(err, errReadOnly):
		status, code, msg = http.StatusForbidden, "read_only", err.Error()
	case errors.Is(err, ErrExists):
		status, code, msg = http.StatusConflict, "exists", err.Error()
	case errors.Is(err, ErrLastUser):
		status, code, msg = http.StatusConflict, "last_user", err.Error()
	case errors.Is(err, ErrNotFound):
		status, code, msg = http.StatusNotFound, "not_found", err.Error()
	case isValidationError(err):
		status, code, msg = http.StatusBadRequest, "invalid", err.Error()
	default:
		status, code = http.StatusBadGateway, "database"
		msg = "the database returned an error; check the service logs"
	}

	s.log.Error("request failed",
		"method", r.Method, "path", r.URL.Path, "admin", adminUserOf(r),
		"status", status, "err", err.Error())
	writeJSON(w, status, errorResponse{Error: msg, Code: code})
}
