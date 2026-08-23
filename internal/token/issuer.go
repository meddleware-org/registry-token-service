package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessClaim is an element of the "access" JWT claim required by the
// Distribution registry token auth specification.
type AccessClaim struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// registryClaims is a custom claim set for the Distribution registry token auth
// protocol. It uses a plain string for "aud" because the distribution/registry
// v3 token parser expects "aud" as a JSON string, not a JSON array (which is
// what golang-jwt/jwt/v5 RegisteredClaims.Audience always produces).
type registryClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"` // plain string, not []string
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	JWTID    string `json:"jti"`

	Access []AccessClaim `json:"access"`
}

// Valid implements jwt.Claims so golang-jwt can sign the struct.
func (r registryClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(r.Expiry, 0)), nil
}
func (r registryClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(r.IssuedAt, 0)), nil
}
func (r registryClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (r registryClaims) GetIssuer() (string, error)              { return r.Issuer, nil }
func (r registryClaims) GetSubject() (string, error)             { return r.Subject, nil }
func (r registryClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{r.Audience}, nil
}

// Issuer signs JWTs for the Distribution registry token auth protocol.
type Issuer struct {
	issuer  string
	service string
	ttl     time.Duration
	key     *rsa.PrivateKey
	kid     string // JWK SHA-256 thumbprint (RFC 7638) of the signing public key
}

// jwkThumbprintRSA computes the RFC 7638 JWK thumbprint for an RSA public key.
// The distribution registry v3 uses this as the key ID in the rootcertbundle
// trustedKeys map and requires the JWT header to carry a matching kid.
func jwkThumbprintRSA(pub *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(
		big.NewInt(int64(pub.E)).Bytes(),
	)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	// RFC 7638 §3: members in lexicographic order (e < kty < n), no whitespace.
	// Use fmt.Sprintf to guarantee order; json.Marshal on a map does not.
	payload := []byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`)
	sum := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewIssuer constructs an Issuer.
// issuer is placed in the iss claim; service is placed in the aud claim.
func NewIssuer(issuer, service string, ttl time.Duration, key *rsa.PrivateKey) *Issuer {
	return &Issuer{
		issuer:  issuer,
		service: service,
		ttl:     ttl,
		key:     key,
		kid:     jwkThumbprintRSA(&key.PublicKey),
	}
}

// Sign produces a signed RS256 JWT for the given subject and access list.
// Returns the compact serialization string and the expiry time.
func (i *Issuer) Sign(subject string, access []AccessClaim) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(i.ttl)

	claims := registryClaims{
		Issuer:   i.issuer,
		Subject:  subject,
		Audience: i.service,
		IssuedAt: now.Unix(),
		Expiry:   exp.Unix(),
		JWTID:    uuid.NewString(),
		Access:   access,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Distribution registry v3.1.1 requires the kid header to match the
	// JWK SHA-256 thumbprint stored in its trustedKeys map (populated from
	// rootcertbundle). Without kid, the token falls through to the default
	// branch in VerifySigningKey and is rejected as ErrInvalidToken.
	tok.Header["kid"] = i.kid
	signed, err := tok.SignedString(i.key)
	return signed, exp, err
}
