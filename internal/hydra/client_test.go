package hydra

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestValidateClientCredentials pins the status mapping: only a 200 carrying an access
// token is valid; 401/403 and OAuth errors are invalid; anything else is an error, which
// the handler turns into 503 (fail closed).
func TestValidateClientCredentials(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		valid   bool
		wantErr bool
	}{
		{"issued", 200, `{"access_token":"t","token_type":"bearer"}`, true, false},
		{"unauthorized", 401, `{"error":"invalid_client"}`, false, false},
		{"forbidden", 403, ``, false, false},
		{"oauth error in 200", 200, `{"error":"invalid_scope"}`, false, false},
		{"empty token", 200, `{"token_type":"bearer"}`, false, false},
		{"server error", 500, `boom`, false, true},
		{"malformed", 200, `{`, false, true},
	}
	for _, c := range cases {
		var gotUser, gotPass, gotGrant string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPass, _ = r.BasicAuth()
			_ = r.ParseForm()
			gotGrant = r.PostForm.Get("grant_type")
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		valid, err := NewClient(srv.URL).ValidateClientCredentials(context.Background(), "client", "s3cret")
		srv.Close()
		if valid != c.valid || (err != nil) != c.wantErr {
			t.Errorf("%s: got valid=%v err=%v", c.name, valid, err)
		}
		if gotUser != "client" || gotPass != "s3cret" || gotGrant != "client_credentials" {
			t.Errorf("%s: request carried user=%q grant=%q", c.name, gotUser, gotGrant)
		}
	}
}

func TestValidateClientCredentialsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if valid, err := NewClient(url).ValidateClientCredentials(context.Background(), "c", "s"); valid || err == nil {
		t.Errorf("unreachable Hydra: got valid=%v err=%v, want error", valid, err)
	}
}
