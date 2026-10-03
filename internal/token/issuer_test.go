package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestSignClaims verifies what the registry checks: RS256 with the RFC 7638 kid, iss, a
// string aud equal to the service, sub, iat/exp spanning the TTL, a jti, and the access list.
func TestSignClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // size is enforced by config, not the issuer
	if err != nil {
		t.Fatal(err)
	}
	iss := NewIssuer("token-service", "registry.example", 5*time.Minute, key)
	access := []AccessClaim{{Type: "repository", Name: "org/app", Actions: []string{"pull"}}}
	signed, exp, err := iss.Sign("client", access)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Parse(signed, func(tok *jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience("registry.example"), jwt.WithIssuer("token-service"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Header["kid"] != jwkThumbprintRSA(&key.PublicKey) {
		t.Errorf("kid %v is not the key's RFC 7638 thumbprint", parsed.Header["kid"])
	}

	payload, _ := jwt.NewParser().DecodeSegment(strings.Split(signed, ".")[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if _, isString := claims["aud"].(string); !isString {
		t.Errorf("aud must be a JSON string for distribution v3, got %T", claims["aud"])
	}
	if claims["sub"] != "client" || claims["jti"] == "" {
		t.Errorf("sub/jti: %v", claims)
	}
	iat, expClaim := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if expClaim-iat != 300 || expClaim != exp.Unix() {
		t.Errorf("iat=%d exp=%d returned=%d, want a 300 s span", iat, expClaim, exp.Unix())
	}
	got, _ := json.Marshal(claims["access"])
	if string(got) != `[{"actions":["pull"],"name":"org/app","type":"repository"}]` {
		t.Errorf("access claim: %s", got)
	}
}

// TestThumbprintMatchesRFC7638 checks the kid against the RFC 7638 §3.1 example key.
func TestThumbprintMatchesRFC7638(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	pub := &rsa.PublicKey{E: 65537}
	b, err := jwt.NewParser().DecodeSegment(n)
	if err != nil {
		t.Fatal(err)
	}
	pub.N = new(big.Int).SetBytes(b)
	if got := jwkThumbprintRSA(pub); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("thumbprint %s", got)
	}
}
