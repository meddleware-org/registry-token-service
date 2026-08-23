// Package config loads server configuration from environment variables.
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// minRSABits is the minimum accepted RSA modulus size for the JWT signing key.
// The Distribution registry validates RS256 tokens; a key below this size weakens
// every issued token, so the service refuses to start with a smaller key.
const minRSABits = 4096

// Config holds all runtime configuration for the token service.
type Config struct {
	// Port is the HTTP listen port.
	Port string

	// TokenIssuer is the iss claim placed in issued JWTs (e.g. "https://token.meddleware.co.uk").
	TokenIssuer string

	// TokenService is the aud claim and the registry service name the token targets
	// (e.g. "registry.meddleware.co.uk").
	TokenService string

	// TokenTTL is the lifetime of issued tokens.
	TokenTTL time.Duration

	// PrivateKey is the RSA private key used to sign JWTs.
	PrivateKey *rsa.PrivateKey

	// HydraTokenURL is the Hydra public OAuth2 token endpoint used to validate
	// client credentials (e.g. "http://hydra.auth.svc.cluster.local:4444/oauth2/token").
	HydraTokenURL string

	// KetoReadURL is the base URL of the Keto read API
	// (e.g. "http://keto.auth.svc.cluster.local:4466").
	KetoReadURL string

	// LogLevel is the log verbosity ("info", "debug", "warn", "error").
	LogLevel string
}

// Load reads configuration from environment variables and returns a Config.
// Returns an error if any required value is missing or invalid.
func Load() (*Config, error) {
	// Collect all missing required vars before returning so the operator sees
	// all problems in one startup message rather than one-at-a-time.
	var missing []string
	requireEnv := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			missing = append(missing, key)
		}
		return v
	}

	port := envOr("PORT", "8080")
	tokenIssuer := requireEnv("TOKEN_ISSUER")
	tokenService := requireEnv("TOKEN_SERVICE")
	hydraTokenURL := requireEnv("HYDRA_TOKEN_URL")
	ketoReadURL := requireEnv("KETO_READ_URL")
	logLevel := envOr("LOG_LEVEL", "info")

	ttlSec, err := strconv.Atoi(envOr("TOKEN_TTL", "300"))
	if err != nil {
		return nil, fmt.Errorf("TOKEN_TTL must be an integer: %w", err)
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("required environment variables not set: %s", strings.Join(missing, ", "))
	}

	keyPath := envOr("RSA_PRIVATE_KEY_PATH", "/etc/token-service/signing.key")
	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load RSA private key from %s: %w", keyPath, err)
	}
	// Enforce the minimum modulus size. The registry token-signing key MUST be at
	// least 4096-bit — a weaker key silently degrades the security of every issued
	// token. Fail closed at startup rather than sign with a weak key.
	if bits := key.N.BitLen(); bits < minRSABits {
		return nil, fmt.Errorf("RSA signing key is %d-bit; minimum is %d-bit", bits, minRSABits)
	}

	return &Config{
		Port:          port,
		TokenIssuer:   tokenIssuer,
		TokenService:  tokenService,
		TokenTTL:      time.Duration(ttlSec) * time.Second,
		PrivateKey:    key,
		HydraTokenURL: hydraTokenURL,
		KetoReadURL:   ketoReadURL,
		LogLevel:      logLevel,
	}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}
