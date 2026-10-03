package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	keyOnce sync.Once
	key4096 *rsa.PrivateKey
)

// strongKey generates one 4096-bit key for the whole package (slow to generate).
func strongKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatal(err)
		}
		key4096 = k
	})
	return key4096
}

func writeKey(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// setValidEnv sets every required variable to a valid value and points at keyPath.
func setValidEnv(t *testing.T, keyPath string) {
	t.Helper()
	t.Setenv("TOKEN_ISSUER", "registry-token-service")
	t.Setenv("TOKEN_SERVICE", "registry.example")
	t.Setenv("HYDRA_TOKEN_URL", "http://hydra:4444/oauth2/token")
	t.Setenv("KETO_READ_URL", "http://keto:4466")
	t.Setenv("TOKEN_TTL", "")
	t.Setenv("RSA_PRIVATE_KEY_PATH", keyPath)
}

func TestLoadValid(t *testing.T) {
	k := strongKey(t)
	for _, c := range []struct {
		name, blockType string
		der             func() []byte
	}{
		{"PKCS1", "RSA PRIVATE KEY", func() []byte { return x509.MarshalPKCS1PrivateKey(k) }},
		{"PKCS8", "PRIVATE KEY", func() []byte { b, _ := x509.MarshalPKCS8PrivateKey(k); return b }},
	} {
		setValidEnv(t, writeKey(t, c.blockType, c.der()))
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if cfg.TokenTTL.Seconds() != 300 || cfg.Port != "8080" || cfg.PrivateKey.N.BitLen() != 4096 {
			t.Errorf("%s: unexpected config %+v", c.name, cfg)
		}
	}
}

func TestLoadRefusesWeakOrUnsupportedKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	setValidEnv(t, writeKey(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(weak)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "minimum is 4096-bit") {
		t.Errorf("2048-bit key: got %v", err)
	}
	setValidEnv(t, writeKey(t, "EC PRIVATE KEY", []byte{1, 2, 3}))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "unsupported PEM block type") {
		t.Errorf("EC block: got %v", err)
	}
	setValidEnv(t, filepath.Join(t.TempDir(), "missing.key"))
	if _, err := Load(); err == nil {
		t.Error("missing key file: want error")
	}
}

func TestLoadRefusesBadSettings(t *testing.T) {
	path := writeKey(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(strongKey(t)))
	cases := []struct{ key, value, want string }{
		{"TOKEN_SERVICE", "", "TOKEN_SERVICE"},
		{"HYDRA_TOKEN_URL", "ftp://hydra/token", "HYDRA_TOKEN_URL must be an http(s) URL"},
		{"KETO_READ_URL", "http://", "KETO_READ_URL must include a host"},
		{"TOKEN_TTL", "abc", "TOKEN_TTL must be an integer"},
		{"TOKEN_TTL", "0", "TOKEN_TTL must be between"},
		{"TOKEN_TTL", "86400", "TOKEN_TTL must be between"},
	}
	for _, c := range cases {
		setValidEnv(t, path)
		t.Setenv(c.key, c.value)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s=%q: got %v, want error containing %q", c.key, c.value, err, c.want)
		}
	}
}
