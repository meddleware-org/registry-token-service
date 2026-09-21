// Package main implements the registry token service for the CNCF Distribution
// registry token auth specification (https://distribution.github.io/distribution/spec/auth/token/).
//
// The service authenticates Docker clients via HTTP Basic auth forwarded to Ory
// Hydra's client_credentials grant, then checks per-repository push/pull
// permissions in Ory Keto, and issues RS256-signed JWTs that the Distribution
// registry validates directly.
//
// Environment variables:
//
//	PORT               — HTTP listen port (default: 8080)
//	TOKEN_ISSUER       — iss claim in issued JWTs (e.g. https://token.meddleware.co.uk)
//	TOKEN_SERVICE      — aud claim and registry service name (e.g. registry.meddleware.co.uk)
//	TOKEN_TTL          — token lifetime in seconds (default: 300)
//	RSA_PRIVATE_KEY_PATH — path to PEM RSA private key file
//	HYDRA_TOKEN_URL    — Hydra public token endpoint (POST /oauth2/token)
//	KETO_READ_URL      — Keto read API base URL
//	LOG_LEVEL          — info | debug | warn | error (default: info)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/meddleware-org/registry-token-service/internal/config"
	"github.com/meddleware-org/registry-token-service/internal/hydra"
	"github.com/meddleware-org/registry-token-service/internal/keto"
	"github.com/meddleware-org/registry-token-service/internal/token"
)

func main() {
	// `-healthcheck` mode is used by the container HEALTHCHECK on non-Kubernetes
	// runtimes (Docker/Compose). It dials the local /healthz endpoint and exits
	// 0 (healthy) or 1 (unhealthy). It runs before config.Load so it needs no
	// signing key or auth backends — only PORT (default 8080).
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthCheck())
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	hydraClient := hydra.NewClient(cfg.HydraTokenURL)
	ketoClient := keto.NewClient(cfg.KetoReadURL)
	issuer := token.NewIssuer(cfg.TokenIssuer, cfg.TokenService, cfg.TokenTTL, cfg.PrivateKey)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.Handle("GET /token", handleToken(hydraClient, ketoClient, issuer, cfg.TokenService))

	srv := &http.Server{
		Addr:         net.JoinHostPort("", cfg.Port),
		Handler:      logRequest(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
	slog.Info("shutdown complete")
}

// healthCheck dials the local /healthz endpoint and returns a process exit code
// (0 = healthy, 1 = unhealthy). Used by the container HEALTHCHECK instruction.
func healthCheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/healthz", port))
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// handleHealth responds 200 OK to liveness and readiness probes.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// tokenResponse is the JSON body returned to a Docker client on success.
// The "issued_at" field uses RFC3339 format as required by the spec.
type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	IssuedAt  string `json:"issued_at"`
}

// handleToken processes GET /token requests from Docker clients.
// Query parameters:
//
//	service — registry hostname, must match TOKEN_SERVICE
//	scope   — space-separated "type:name:actions" scope strings
//	account — Docker username (informational; clientID from Basic auth is used)
func handleToken(
	hydraClient *hydra.Client,
	ketoClient *keto.Client,
	issuer *token.Issuer,
	service string,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry token service"`)
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// The `service` param must name this token service (it becomes the JWT `aud`); a mismatch
		// means the token would be minted for a different audience than the registry validating it,
		// so reject it rather than issue a token the registry will reject anyway.
		if svc := r.URL.Query().Get("service"); svc != service {
			slog.Warn("service mismatch", "client_id", clientID, "requested_service", svc, "expected", service)
			writeError(w, http.StatusBadRequest, "unexpected service")
			return
		}

		ctx := r.Context()

		// Step 1: validate client credentials against Hydra.
		valid, err := hydraClient.ValidateClientCredentials(ctx, clientID, clientSecret)
		if err != nil {
			slog.Error("hydra validation error", "client_id", clientID, "err", err)
			writeError(w, http.StatusServiceUnavailable, "auth service unavailable")
			return
		}
		if !valid {
			slog.Warn("invalid client credentials", "client_id", clientID)
			w.Header().Set("WWW-Authenticate", `Basic realm="registry token service"`)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Step 2: evaluate requested scope against Keto.
		rawScope := r.URL.Query().Get("scope")
		scopeItems := token.ParseScope(rawScope)

		var access []token.AccessClaim
		for _, item := range scopeItems {
			switch {
			case item.Type == "repository":
				// Per-action push/pull/delete: check each against Keto, first on
				// the specific repository object and then, as a fallback, on the
				// repository's org object (see checkRepoOrOrgPermission).
				var allowed []string
				for _, action := range item.Actions {
					relation := actionToRelation(action)
					if relation == "" {
						continue
					}
					permitted, err := checkRepoOrOrgPermission(ctx, ketoClient, item.Name, relation, clientID)
					if err != nil {
						slog.Error("keto check error", "client_id", clientID, "repo", item.Name, "action", action, "err", err)
						writeError(w, http.StatusServiceUnavailable, "authz service unavailable")
						return
					}
					if permitted {
						allowed = append(allowed, action)
					}
				}
				filtered := item.FilterActions(allowed)
				if filtered != nil {
					access = append(access, token.AccessClaim{
						Type:    filtered.Type,
						Name:    filtered.Name,
						Actions: filtered.Actions,
					})
				}
			case item.Type == "registry" && item.Name == "catalog":
				// Catalog listing: single Keto check on Registry:catalog#listers.
				permitted, err := ketoClient.CheckPermission(ctx, "Registry", "catalog", "listers", clientID)
				if err != nil {
					slog.Error("keto check error", "client_id", clientID, "object", "catalog", "relation", "listers", "err", err)
					writeError(w, http.StatusServiceUnavailable, "authz service unavailable")
					return
				}
				if permitted {
					access = append(access, token.AccessClaim{
						Type:    "registry",
						Name:    "catalog",
						Actions: []string{"*"},
					})
				}
				// All other scope types are silently dropped.
			}
		}

		// Step 3: sign and return the JWT.
		signed, exp, err := issuer.Sign(clientID, access)
		if err != nil {
			slog.Error("token signing error", "err", err)
			writeError(w, http.StatusInternalServerError, "token signing failed")
			return
		}

		now := time.Now().UTC()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Token:     signed,
			ExpiresIn: int(exp.Sub(now).Seconds()),
			IssuedAt:  now.Format(time.RFC3339),
		})

		slog.Info("token issued",
			"client_id", clientID,
			"scope_items", len(access),
		)
	})
}

// checkRepoOrOrgPermission grants an action if the client holds relation on the
// specific repository object, or — failing that — on the repository's org
// object (the path segment before the first "/"). The repo-level tuple is the
// fine-grained override; the org-level tuple is the broad default that lets new
// repositories be pushed/pulled without adding a per-repo tuple for every image.
//
// A repo name without a "/" (no org segment) is checked only at the repo level.
// Either check may return an error (e.g. Keto unreachable), which the caller
// turns into a 503 — the service never fails open.
func checkRepoOrOrgPermission(ctx context.Context, ketoClient *keto.Client, repo, relation, clientID string) (bool, error) {
	permitted, err := ketoClient.CheckPermission(ctx, "Registry", repo, relation, clientID)
	if err != nil {
		return false, err
	}
	if permitted {
		return true, nil
	}

	org := orgOf(repo)
	if org == "" {
		return false, nil
	}
	return ketoClient.CheckPermission(ctx, "Registry", org, relation, clientID)
}

// orgOf returns the organization segment of a repository name — the portion
// before the first "/". For "meddleware-org/registry-auth-proxy" it returns
// "meddleware-org"; for a name with no "/" it returns "".
func orgOf(repo string) string {
	if i := strings.IndexByte(repo, '/'); i > 0 {
		return repo[:i]
	}
	return ""
}

// actionToRelation maps a Docker registry action string to the corresponding
// Keto relation name in the Registry namespace.
func actionToRelation(action string) string {
	switch action {
	case "pull":
		return "pullers"
	case "push":
		return "pushers"
	case "delete":
		return "admins"
	default:
		return ""
	}
}

// writeError writes a JSON error body with the given HTTP status.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// responseWriter wraps http.ResponseWriter to capture the status code for logging.
type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

// logRequest logs method, path, status, and elapsed time for each request.
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rw, r)
		slog.Debug("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.code,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
	})
}
