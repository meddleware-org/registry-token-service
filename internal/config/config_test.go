// Tests for configuration loading: required variables, URL validation (and that a rejected URL is never repeated), the lifetime range and the signing-key checks.

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

// One 4096-bit key is generated for the whole package, because generating it is slow.
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

// writeKey writes one PEM block of the given type to a temporary file and returns its path.
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

// TestLoadValid checks a valid environment loads, with the key in either supported format.
func TestLoadValid(t *testing.T) {
	// One shared strong key; only the settings under test vary.
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

// TestLoadRefusesWeakOrUnsupportedKeys checks keys below the 4096-bit floor, non-RSA keys, unknown PEM types and a missing file are refused.
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

// TestLoadRefusesBadSettings checks each invalid setting (a missing service, a bad URL, a bad or out-of-range lifetime) is refused with a message naming the variable.
func TestLoadRefusesBadSettings(t *testing.T) {
	path := writeKey(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(strongKey(t)))
	// Each row: the variable to break, the bad value, and the text the error must contain (it names the variable).
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

// TestURLErrorsNeverEchoTheValue checks a rejected URL is named by its variable only: values carrying a user name,
// password, path token and query key (including ones that parse with a secret-looking scheme) must reach no part of
// the error, which is logged.
func TestURLErrorsNeverEchoTheValue(t *testing.T) {
	path := writeKey(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(strongKey(t)))
	for _, raw := range []string{
		"ftp://user:s3cret@host.example/tok3n?key=k3y",
		"s3cret:pw@host.example",
		"https://user:s3cret@",
		"https://us:s3cret@[::1",
	} {
		setValidEnv(t, path)
		t.Setenv("HYDRA_TOKEN_URL", raw)
		_, err := Load()
		if err == nil {
			t.Fatalf("HYDRA_TOKEN_URL=%q: want an error", raw)
		}
		for _, part := range []string{"user", "s3cret", "host.example", "tok3n", "k3y", "pw@", "ftp"} {
			if strings.Contains(err.Error(), part) {
				t.Errorf("error %q repeats %q", err, part)
			}
		}
		if !strings.Contains(err.Error(), "HYDRA_TOKEN_URL") {
			t.Errorf("error %q does not name the variable", err)
		}
	}
}
