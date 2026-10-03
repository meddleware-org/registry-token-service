package keto

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCheckPermission pins the status mapping: 200 follows "allowed"; 403 is a denial;
// anything else, or a malformed body, is an error (the handler answers 503, never allows).
func TestCheckPermission(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		allowed bool
		wantErr bool
	}{
		{"allowed", 200, `{"allowed":true}`, true, false},
		{"denied in 200", 200, `{"allowed":false}`, false, false},
		{"denied 403", 403, `{"allowed":false}`, false, false},
		{"server error", 500, `x`, false, true},
		{"not found", 404, ``, false, true},
		{"malformed", 200, `{"allowed":`, false, true},
	}
	for _, c := range cases {
		var query map[string]string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			query = map[string]string{"path": r.URL.Path, "namespace": q.Get("namespace"), "object": q.Get("object"), "relation": q.Get("relation"), "subject_id": q.Get("subject_id")}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		allowed, err := NewClient(srv.URL).CheckPermission(context.Background(), "Registry", "org/repo&x=1", "pushers", "client")
		srv.Close()
		if allowed != c.allowed || (err != nil) != c.wantErr {
			t.Errorf("%s: got allowed=%v err=%v", c.name, allowed, err)
		}
		if query["path"] != "/relation-tuples/check" || query["namespace"] != "Registry" || query["object"] != "org/repo&x=1" ||
			query["relation"] != "pushers" || query["subject_id"] != "client" {
			t.Errorf("%s: request was %v (object must arrive intact, not split into parameters)", c.name, query)
		}
	}
}
