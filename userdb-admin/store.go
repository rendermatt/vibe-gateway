package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schema is applied on every boot. Usernames are stored as given but are unique
// case-insensitively, so "Alice" and "alice" can't both exist -- otherwise a
// delete could appear to succeed while the other row still authenticates.
const schema = `
CREATE TABLE IF NOT EXISTS gateway_users (
    username      TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS gateway_users_username_lower_idx
    ON gateway_users (lower(username));
`

// lockKey is the advisory-lock id guarding the count-then-delete in Delete.
// Any constant works as long as nothing else in the database uses it.
const lockKey = 0x75736572_64620001

type Store struct{ pool *pgxpool.Pool }

type User struct {
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func NewStore(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	// The auth path runs on every gateway request, so keep a warm pool and fail
	// fast rather than queueing behind a slow database.
	cfg.MaxConns = 10
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) List(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, created_at, updated_at FROM gateway_users ORDER BY lower(username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Lookup returns the stored hash for a username. It returns ErrNotFound rather
// than an empty string so callers can't accidentally treat "no such user" as
// "empty password".
func (s *Store) Lookup(ctx context.Context, username string) (string, error) {
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT password_hash FROM gateway_users WHERE lower(username) = lower($1)`, username).
		Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (s *Store) Add(ctx context.Context, username, hash string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO gateway_users (username, password_hash) VALUES ($1, $2)`, username, hash)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return fmt.Errorf("%w: %q", ErrExists, username)
	}
	return err
}

func (s *Store) SetHash(ctx context.Context, username, hash string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE gateway_users SET password_hash = $2, updated_at = now() WHERE lower(username) = lower($1)`,
		username, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %q", ErrNotFound, username)
	}
	return nil
}

// Delete refuses to remove the last account. The count and the delete run in one
// transaction under an advisory lock, so two concurrent deletes can't each see
// two rows and leave the table empty between them.
func (s *Store) Delete(ctx context.Context, username string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockKey)); err != nil {
		return err
	}

	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM gateway_users`).Scan(&n); err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastUser
	}

	tag, err := tx.Exec(ctx, `DELETE FROM gateway_users WHERE lower(username) = lower($1)`, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %q", ErrNotFound, username)
	}
	return tx.Commit(ctx)
}

func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_users`).Scan(&n)
	return n, err
}
