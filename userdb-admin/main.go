package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed static
var staticFiles embed.FS

type config struct {
	port         string
	databaseURL  string
	gatewayToken string
	adminUser    string
	adminHash    string
	bcryptCost   int
	credTTL      time.Duration
	readOnly     bool
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func loadConfig() (config, error) {
	c := config{
		port:         env("PORT", "10000"),
		databaseURL:  os.Getenv("DATABASE_URL"),
		gatewayToken: os.Getenv("GATEWAY_TOKEN"),
		adminUser:    env("ADMIN_USER", ""),
		adminHash:    os.Getenv("ADMIN_PASSWORD_HASH"),
		readOnly:     envBool("READ_ONLY", false),
	}
	cost, err := strconv.Atoi(env("BCRYPT_COST", "12"))
	if err != nil || cost < bcrypt.MinCost || cost > 15 {
		return c, fmt.Errorf("BCRYPT_COST must be an integer in [%d,15]", bcrypt.MinCost)
	}
	c.bcryptCost = cost

	ttlSec, err := strconv.Atoi(env("CRED_CACHE_TTL_SECONDS", "300"))
	if err != nil || ttlSec < 0 || ttlSec > 3600 {
		return c, errors.New("CRED_CACHE_TTL_SECONDS must be an integer in [0,3600]")
	}
	c.credTTL = time.Duration(ttlSec) * time.Second

	required := []struct{ key, val string }{
		{"DATABASE_URL", c.databaseURL},
		{"GATEWAY_TOKEN", c.gatewayToken},
		{"ADMIN_USER", c.adminUser},
		{"ADMIN_PASSWORD_HASH", c.adminHash},
	}
	var missing []string
	for _, r := range required {
		if strings.TrimSpace(r.val) == "" {
			missing = append(missing, r.key)
		}
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	// A short token would make the auth endpoint brute-forceable from the public
	// internet, which is the one thing it exists to prevent.
	if len(c.gatewayToken) < 24 {
		return c, fmt.Errorf("GATEWAY_TOKEN must be at least 24 characters, got %d", len(c.gatewayToken))
	}
	if _, err := bcrypt.Cost([]byte(c.adminHash)); err != nil {
		return c, fmt.Errorf("ADMIN_PASSWORD_HASH is not a valid bcrypt hash: %w", err)
	}
	if err := validateUsername(c.adminUser); err != nil {
		return c, fmt.Errorf("ADMIN_USER: %w", err)
	}
	return c, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig()
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}

	startCtx, cancelStart := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStart()
	store, err := NewStore(startCtx, cfg.databaseURL)
	if err != nil {
		log.Error("database unavailable at startup", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	s := &server{
		cfg:   cfg,
		store: store,
		auth:  newAuthenticator(cfg.adminUser, cfg.adminHash),
		creds: newCredCache(cfg.credTTL),
		log:   log,
	}

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Error("embed", "err", err)
		os.Exit(1)
	}

	// Admin surface: everything here sits behind admin basic auth.
	admin := http.NewServeMux()
	admin.Handle("/api/users", http.HandlerFunc(s.handleListUsers))
	admin.Handle("/api/users/add", requireCSRFHeader(http.HandlerFunc(s.handleAddUser)))
	admin.Handle("/api/users/reset", requireCSRFHeader(http.HandlerFunc(s.handleResetUser)))
	admin.Handle("/api/users/delete", requireCSRFHeader(http.HandlerFunc(s.handleDeleteUser)))
	admin.Handle("/", http.FileServer(http.FS(sub)))

	root := http.NewServeMux()

	// The gateway's forward_auth target. NOT behind admin auth -- it carries the
	// end user's credentials, and is gated by the shared GATEWAY_TOKEN instead.
	root.HandleFunc("/auth", s.handleGatewayAuth)

	// Render's health checker sends no credentials, so this is open. It checks
	// the database, because a userdb-admin that cannot reach Postgres cannot
	// authenticate anyone and should not be kept in the load balancer.
	root.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := s.store.Ping(ctx); err != nil {
			log.Error("health check failed", "err", err)
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	root.Handle("/", securityHeaders(s.auth.middleware(admin)))

	httpSrv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		n, err := store.Count(ctx)
		if err != nil {
			log.Warn("could not count users at startup", "err", err)
		} else if n == 0 {
			// Not fatal -- you have to be able to boot an empty system to seed
			// it -- but it means the gateway is rejecting everyone right now.
			log.Warn("there are ZERO gateway users; the gateway will reject every request until you add one")
		}
		log.Info("listening",
			"addr", httpSrv.Addr,
			"users", n,
			"read_only", cfg.readOnly,
			"bcrypt_cost", cfg.bcryptCost,
			"cred_cache_ttl", cfg.credTTL)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}
