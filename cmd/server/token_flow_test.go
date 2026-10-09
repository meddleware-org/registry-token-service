package main

// End-to-end behaviour of GET /token against fake Hydra and Keto servers and a real issuer: the
// rules the AUTH lens asks for (authentication before any authorization call, deny by default, the
// intersection of requested and granted, fail closed on every anchor failure, no cached or
// over-long requests, an audit line that never carries a credential).

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/meddleware-org/registry-token-service/internal/hydra"
	"github.com/meddleware-org/registry-token-service/internal/keto"
	"github.com/meddleware-org/registry-token-service/internal/token"
)

const (
	flowService = "registry.example"
	flowIssuer  = "https://token.example"
	flowTTL     = 5 * time.Minute
)

type anchors struct {
	hydraCalls atomic.Int32
	ketoCalls  atomic.Int32
	hydraSrv   *httptest.Server
	ketoSrv    *httptest.Server
}

// newAnchors starts fake anchors. hydraStatus is the status of the fake token endpoint; granted is
// the set of "object#relation" tuples Keto allows for any subject; ketoBody, when set, replaces the
// Keto response body (a malformed or unexpected one).
func newAnchors(t *testing.T, hydraStatus int, granted map[string]bool, ketoStatus int, ketoBody string) *anchors {
	t.Helper()
	a := &anchors{}
	a.hydraSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a.hydraCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(hydraStatus)
		if hydraStatus == http.StatusOK {
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"bearer"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	a.ketoSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.ketoCalls.Add(1)
		q := r.URL.Query()
		allowed := granted[q.Get("object")+"#"+q.Get("relation")]
		w.Header().Set("Content-Type", "application/json")
		switch {
		case ketoStatus != 0:
			w.WriteHeader(ketoStatus)
			_, _ = w.Write([]byte(ketoBody))
		case !allowed:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"allowed":false}`))
		default:
			_, _ = w.Write([]byte(`{"allowed":true}`))
		}
	}))
	t.Cleanup(a.hydraSrv.Close)
	t.Cleanup(a.ketoSrv.Close)
	return a
}

func newFlow(t *testing.T, a *anchors) (http.Handler, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048) // the 4096-bit floor is enforced by config.Load
	if err != nil {
		t.Fatal(err)
	}
	issuer := token.NewIssuer(flowIssuer, flowService, flowTTL, key)
	return handleToken(hydra.NewClient(a.hydraSrv.URL), keto.NewClient(a.ketoSrv.URL), issuer, flowService), key
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func request(scope string, auth bool) *http.Request {
	q := url.Values{"service": {flowService}, "scope": {scope}}
	req := httptest.NewRequest(http.MethodGet, "/token?"+q.Encode(), nil)
	if auth {
		req.SetBasicAuth("ci-client", "s3cr3t-value")
	}
	return req
}

type issued struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// verify parses an issued token the way the registry does (RS256 only, aud and iss pinned) and
// returns its claims.
func verify(t *testing.T, signed string, key *rsa.PrivateKey) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(signed, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(flowService), jwt.WithIssuer(flowIssuer), jwt.WithLeeway(0))
	if err != nil {
		t.Fatalf("the registry would refuse this token: %v", err)
	}
	return claims
}

func accessOf(t *testing.T, claims jwt.MapClaims) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	list, _ := claims["access"].([]any)
	for _, raw := range list {
		m := raw.(map[string]any)
		var actions []string
		for _, a := range m["actions"].([]any) {
			actions = append(actions, a.(string))
		}
		out[m["type"].(string)+":"+m["name"].(string)] = actions
	}
	return out
}

func TestToken_NoCredentialsNeverReachesAnAnchor(t *testing.T) {
	a := newAnchors(t, http.StatusOK, nil, 0, "")
	h, _ := newFlow(t, a)
	rec := serve(h, request("repository:org/app:pull", false))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("a 401 must carry a Basic challenge, got %q", rec.Header().Get("WWW-Authenticate"))
	}
	if a.hydraCalls.Load() != 0 || a.ketoCalls.Load() != 0 {
		t.Errorf("anchors called without credentials: hydra=%d keto=%d", a.hydraCalls.Load(), a.ketoCalls.Load())
	}
}

func TestToken_InvalidCredentialsAreRefusedBeforeAuthorization(t *testing.T) {
	a := newAnchors(t, http.StatusUnauthorized, map[string]bool{"org/app#pullers": true}, 0, "")
	h, _ := newFlow(t, a)
	rec := serve(h, request("repository:org/app:pull", true))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if a.ketoCalls.Load() != 0 {
		t.Errorf("Keto was asked about a client Hydra rejected (%d calls)", a.ketoCalls.Load())
	}
	// The same body whatever failed: nothing tells a caller whether the client id exists.
	if !strings.Contains(rec.Body.String(), "invalid credentials") || strings.Contains(rec.Body.String(), "ci-client") {
		t.Errorf("body %q must be uniform and not echo the client", rec.Body.String())
	}
}

func TestToken_GrantIsTheIntersectionOfRequestedAndGranted(t *testing.T) {
	a := newAnchors(t, http.StatusOK, map[string]bool{"org/app#pullers": true}, 0, "")
	h, key := newFlow(t, a)
	rec := serve(h, request("repository:org/app:push,pull,delete", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body issued
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	claims := verify(t, body.Token, key)
	got := accessOf(t, claims)
	if len(got) != 1 || strings.Join(got["repository:org/app"], ",") != "pull" {
		t.Fatalf("access = %v, want only pull on org/app (no error, no widening)", got)
	}
	if claims["sub"] != "ci-client" {
		t.Errorf("sub = %v, want the authenticated client", claims["sub"])
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); time.Duration(exp-iat)*time.Second != flowTTL {
		t.Errorf("exp-iat = %vs, want the %v TTL", exp-iat, flowTTL)
	}
	if body.ExpiresIn <= 0 || body.ExpiresIn > int(flowTTL.Seconds()) {
		t.Errorf("expires_in = %d, want within (0, %d]", body.ExpiresIn, int(flowTTL.Seconds()))
	}
	// A bearer token must never be cached by anything between the service and the client.
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Errorf("token response lacks no-store: %v", rec.Header())
	}
}

func TestToken_DenyByDefaultAndEmptyAccessIsStillA200(t *testing.T) {
	a := newAnchors(t, http.StatusOK, nil, 0, "")
	h, key := newFlow(t, a)
	for _, scope := range []string{"", "repository:org/app:push", "registry:catalog:*", "repository:org/app:"} {
		rec := serve(h, request(scope, true))
		if rec.Code != http.StatusOK {
			t.Fatalf("scope %q: status %d, want 200 with an empty access list", scope, rec.Code)
		}
		var body issued
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if got := accessOf(t, verify(t, body.Token, key)); len(got) != 0 {
			t.Errorf("scope %q: access %v granted with nothing in Keto", scope, got)
		}
	}
}

func TestToken_OrgGrantAppliesToItsRepositoriesAndCatalogNeedsListers(t *testing.T) {
	a := newAnchors(t, http.StatusOK, map[string]bool{"org#pushers": true, "catalog#listers": true}, 0, "")
	h, key := newFlow(t, a)
	rec := serve(h, request("repository:org/brand-new:push registry:catalog:*", true))
	var body issued
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	got := accessOf(t, verify(t, body.Token, key))
	if strings.Join(got["repository:org/brand-new"], ",") != "push" || strings.Join(got["registry:catalog"], ",") != "*" {
		t.Fatalf("access = %v", got)
	}
}

func TestToken_UnknownTypesAndActionsGrantNothing(t *testing.T) {
	a := newAnchors(t, http.StatusOK, map[string]bool{"org/app#pullers": true, "org/app#pushers": true}, 0, "")
	h, key := newFlow(t, a)
	rec := serve(h, request("registry:other:* repository:org/app:admin,pull", true))
	var body issued
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	got := accessOf(t, verify(t, body.Token, key))
	if len(got) != 1 || strings.Join(got["repository:org/app"], ",") != "pull" {
		t.Fatalf("access = %v, want only pull on org/app (the unknown action and type are dropped)", got)
	}
}

func TestToken_MalformedRepositoryNamesNeverReachKeto(t *testing.T) {
	a := newAnchors(t, http.StatusOK, map[string]bool{"Org/App#pullers": true, "a/../b#pullers": true}, 0, "")
	h, key := newFlow(t, a)
	long := strings.Repeat("a", 256)
	rec := serve(h, request("repository:Org/App:pull repository:a/../b:pull repository:"+long+":pull repository:org//x:pull repository:org/x#y:pull", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body issued
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if got := accessOf(t, verify(t, body.Token, key)); len(got) != 0 {
		t.Fatalf("access = %v granted for malformed names", got)
	}
	if n := a.ketoCalls.Load(); n != 0 {
		t.Errorf("Keto was asked %d times about names that are not repository names", n)
	}
}

func TestToken_RequestsAreBounded(t *testing.T) {
	a := newAnchors(t, http.StatusOK, nil, 0, "")
	h, _ := newFlow(t, a)

	many := strings.TrimSpace(strings.Repeat("repository:org/app:pull ", token.MaxScopeItems+1))
	if rec := serve(h, request(many, true)); rec.Code != http.StatusBadRequest {
		t.Errorf("%d scope entries: status %d, want 400", token.MaxScopeItems+1, rec.Code)
	}
	long := "repository:org/app:" + strings.Repeat("pull,", token.MaxScopeBytes)
	if rec := serve(h, request(long, true)); rec.Code != http.StatusBadRequest {
		t.Errorf("%d-byte scope: status %d, want 400", len(long), rec.Code)
	}
	if n := a.ketoCalls.Load(); n != 0 {
		t.Errorf("Keto was asked %d times for requests that were refused as too large", n)
	}
	exactly := strings.TrimSpace(strings.Repeat("repository:org/app:pull ", token.MaxScopeItems))
	if rec := serve(h, request(exactly, true)); rec.Code != http.StatusOK {
		t.Errorf("%d scope entries: status %d, want 200", token.MaxScopeItems, rec.Code)
	}
}

func TestToken_EveryAnchorFailureIsA503(t *testing.T) {
	cases := []struct {
		name string
		a    func(t *testing.T) *anchors
	}{
		{"hydra 500", func(t *testing.T) *anchors { return newAnchors(t, http.StatusInternalServerError, nil, 0, "") }},
		{"keto 500", func(t *testing.T) *anchors {
			return newAnchors(t, http.StatusOK, nil, http.StatusInternalServerError, "boom")
		}},
		{"keto 404", func(t *testing.T) *anchors { return newAnchors(t, http.StatusOK, nil, http.StatusNotFound, "") }},
		{"keto malformed 200", func(t *testing.T) *anchors { return newAnchors(t, http.StatusOK, nil, http.StatusOK, "not json") }},
		{"keto empty 200", func(t *testing.T) *anchors { return newAnchors(t, http.StatusOK, nil, http.StatusOK, "") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newFlow(t, c.a(t))
			rec := serve(h, request("repository:org/app:pull", true))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503 (an anchor failure must never allow or deny by guesswork)", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "boom") || strings.Contains(rec.Body.String(), "keto") {
				t.Errorf("anchor detail leaked to the caller: %q", rec.Body.String())
			}
		})
	}
}

func TestToken_AnUnreachableAnchorIsA503(t *testing.T) {
	a := newAnchors(t, http.StatusOK, nil, 0, "")
	h, _ := newFlow(t, a)
	a.ketoSrv.Close()
	if rec := serve(h, request("repository:org/app:pull", true)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Keto down: status %d, want 503", rec.Code)
	}
	a.hydraSrv.Close()
	if rec := serve(h, request("repository:org/app:pull", true)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Hydra down: status %d, want 503", rec.Code)
	}
}

func TestToken_AuditLineNamesWhatWasGrantedAndNeverTheSecret(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	a := newAnchors(t, http.StatusOK, map[string]bool{"org/app#pullers": true}, 0, "")
	h, _ := newFlow(t, a)
	serve(h, request("repository:org/app:pull,push", true))
	serve(h, func() *http.Request {
		r := request("repository:org/app:pull", false)
		r.SetBasicAuth("ci-client", "wrong-secret-xyz")
		return r
	}())

	out := buf.String()
	for _, want := range []string{`"msg":"token issued"`, `"client_id":"ci-client"`, "repository:org/app:pull,push", "repository:org/app:pull"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit log lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"s3cr3t-value", "wrong-secret-xyz"} {
		if strings.Contains(out, secret) {
			t.Errorf("a client secret reached the log: %q", secret)
		}
	}
}

func TestToken_ServiceMustNameThisService(t *testing.T) {
	a := newAnchors(t, http.StatusOK, nil, 0, "")
	h, _ := newFlow(t, a)
	req := httptest.NewRequest(http.MethodGet, "/token?service=other.example&scope=repository:org/app:pull", nil)
	req.SetBasicAuth("ci-client", "s3cr3t-value")
	if rec := serve(h, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if a.hydraCalls.Load() != 0 {
		t.Errorf("Hydra was called for a request addressed to another service")
	}
}
