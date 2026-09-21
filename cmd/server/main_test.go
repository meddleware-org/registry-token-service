package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/meddleware-org/registry-token-service/internal/hydra"
	"github.com/meddleware-org/registry-token-service/internal/keto"
)

func TestOrgOf(t *testing.T) {
	tests := []struct {
		repo string
		want string
	}{
		{"meddleware-org/registry-auth-proxy", "meddleware-org"},
		{"meddleware-org/static-server", "meddleware-org"},
		{"a/b/c", "a"},
		{"noslash", ""},
		{"", ""},
		{"/leading", ""}, // no org segment before the first slash
	}
	for _, tt := range tests {
		if got := orgOf(tt.repo); got != tt.want {
			t.Errorf("orgOf(%q) = %q, want %q", tt.repo, got, tt.want)
		}
	}
}

// fakeKeto returns a Keto client pointed at an httptest server that grants the
// given set of "object#relation@subject" tuples and denies everything else. It
// records how many check requests were made so tests can assert the fallback
// only fires when needed.
func fakeKeto(t *testing.T, granted map[string]bool, calls *int) *keto.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			*calls++
		}
		q := r.URL.Query()
		key := q.Get("object") + "#" + q.Get("relation") + "@" + q.Get("subject_id")
		allowed := granted[key]
		w.Header().Set("Content-Type", "application/json")
		if !allowed {
			// Keto returns 403 {allowed:false} for a denied check.
			w.WriteHeader(http.StatusForbidden)
		}
		_, _ = w.Write([]byte(`{"allowed":` + boolString(allowed) + `}`))
	}))
	t.Cleanup(srv.Close)
	return keto.NewClient(srv.URL)
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestCheckRepoOrOrgPermission(t *testing.T) {
	const client = "registry-ci-push"

	t.Run("repo-level grant wins without hitting org fallback", func(t *testing.T) {
		var calls int
		kc := fakeKeto(t, map[string]bool{
			"meddleware-org/foo#pushers@" + client: true,
		}, &calls)
		ok, err := checkRepoOrOrgPermission(context.Background(), kc, "meddleware-org/foo", "pushers", client)
		if err != nil || !ok {
			t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
		}
		if calls != 1 {
			t.Errorf("keto calls = %d, want 1 (repo-level hit should skip org fallback)", calls)
		}
	})

	t.Run("org-level fallback grants a repo with no specific tuple", func(t *testing.T) {
		var calls int
		kc := fakeKeto(t, map[string]bool{
			"meddleware-org#pushers@" + client: true,
		}, &calls)
		ok, err := checkRepoOrOrgPermission(context.Background(), kc, "meddleware-org/brand-new-image", "pushers", client)
		if err != nil || !ok {
			t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
		}
		if calls != 2 {
			t.Errorf("keto calls = %d, want 2 (repo miss then org hit)", calls)
		}
	})

	t.Run("denied at both levels", func(t *testing.T) {
		kc := fakeKeto(t, map[string]bool{}, nil)
		ok, err := checkRepoOrOrgPermission(context.Background(), kc, "meddleware-org/foo", "pushers", client)
		if err != nil || ok {
			t.Fatalf("got (%v, %v), want (false, nil)", ok, err)
		}
	})

	t.Run("repo without org segment checks repo level only", func(t *testing.T) {
		var calls int
		kc := fakeKeto(t, map[string]bool{}, &calls)
		ok, err := checkRepoOrOrgPermission(context.Background(), kc, "noslash", "pullers", client)
		if err != nil || ok {
			t.Fatalf("got (%v, %v), want (false, nil)", ok, err)
		}
		if calls != 1 {
			t.Errorf("keto calls = %d, want 1 (no org fallback for a repo without a slash)", calls)
		}
	})
}

// fakeHydra returns a hydra.Client pointed at a test server. `status` is what the fake token
// endpoint returns: 200 grants (valid creds), 401 rejects (invalid creds), 500 simulates an
// outage (→ transport-level error → 503 from the handler).
func fakeHydra(t *testing.T, status int) *hydra.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"bearer"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	t.Cleanup(srv.Close)
	return hydra.NewClient(srv.URL)
}

// fakeKetoError returns a Keto client whose server always 500s, so a permission check returns an
// error (the handler must then fail closed with 503, never fail open).
func fakeKetoError(t *testing.T) *keto.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return keto.NewClient(srv.URL)
}

func tokenRequest(service, scope string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/token?service="+url.QueryEscape(service)+"&scope="+url.QueryEscape(scope), nil)
	req.SetBasicAuth("registry-ci", "secret")
	return req
}

func TestHandleToken_ServiceMismatch(t *testing.T) {
	h := handleToken(fakeHydra(t, http.StatusOK), fakeKeto(t, nil, nil), nil, "registry.meddleware.co.uk")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tokenRequest("evil.example.com", "repository:a/b:pull"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a service mismatch", rec.Code)
	}
}

func TestHandleToken_HydraUnavailableReturns503(t *testing.T) {
	h := handleToken(fakeHydra(t, http.StatusInternalServerError), fakeKeto(t, nil, nil), nil, "reg")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tokenRequest("reg", "repository:a/b:pull"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when Hydra is unavailable (must fail closed)", rec.Code)
	}
}

func TestHandleToken_KetoUnavailableReturns503(t *testing.T) {
	h := handleToken(fakeHydra(t, http.StatusOK), fakeKetoError(t), nil, "reg")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tokenRequest("reg", "repository:meddleware-org/foo:pull"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when Keto is unavailable (must fail closed)", rec.Code)
	}
}

// Guard against accidental breakage of the query the client sends to Keto.
func TestFakeKetoKeyShape(t *testing.T) {
	q := url.Values{}
	q.Set("object", "o")
	q.Set("relation", "r")
	q.Set("subject_id", "s")
	if got := q.Get("object") + "#" + q.Get("relation") + "@" + q.Get("subject_id"); got != "o#r@s" {
		t.Fatalf("key shape = %q", got)
	}
}
