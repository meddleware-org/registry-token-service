// authz_test.go proves the shadow wrapper never lets the new backend change a decision, and that the PDP maps Keto's names to the OpenFGA model.

package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fake is a Checker with a fixed answer and a call counter.
type fake struct {
	// allow and err are the answer.
	allow bool
	err   error
	// mu guards calls.
	mu    sync.Mutex
	calls int
}

// CheckPermission returns the fixed answer.
func (f *fake) CheckPermission(context.Context, string, string, string, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.allow, f.err
}

// shadowWith builds a Shadow over two fakes, with a log buffer and a wait group the test can wait on.
func shadowWith(primary, secondary Checker) (*Shadow, *bytes.Buffer, *sync.WaitGroup) {
	var buf bytes.Buffer
	wg := &sync.WaitGroup{}
	return &Shadow{Primary: primary, Secondary: secondary, Log: slog.New(slog.NewJSONHandler(&buf, nil)), wg: wg}, &buf, wg
}

// TestShadowReturnsThePrimaryAnswerWhateverTheSecondarySays covers agree, differ and secondary failure: the answer is always the primary's.
func TestShadowReturnsThePrimaryAnswerWhateverTheSecondarySays(t *testing.T) {
	cases := map[string]struct {
		primary, secondary *fake
		want               bool
		logged             string
	}{
		"agree allow":      {&fake{allow: true}, &fake{allow: true}, true, ""},
		"agree deny":       {&fake{}, &fake{}, false, ""},
		"differ":           {&fake{allow: true}, &fake{}, true, "DIFFERENCE"},
		"secondary errors": {&fake{allow: true}, &fake{err: errors.New("down")}, true, "no answer"},
	}
	for name, c := range cases {
		s, buf, wg := shadowWith(c.primary, c.secondary)
		got, err := s.CheckPermission(context.Background(), "Registry", "org", "pushers", "client")
		wg.Wait()
		if err != nil || got != c.want {
			t.Errorf("%s: got %v %v, want %v", name, got, err, c.want)
		}
		if c.logged == "" && buf.Len() != 0 {
			t.Errorf("%s: unexpected log %s", name, buf.String())
		}
		if c.logged != "" && !strings.Contains(buf.String(), c.logged) {
			t.Errorf("%s: log %q lacks %q", name, buf.String(), c.logged)
		}
	}
}

// TestShadowPrimaryErrorFailsClosedAndSkipsTheSecondary: no primary answer is an error and the secondary is never asked.
func TestShadowPrimaryErrorFailsClosedAndSkipsTheSecondary(t *testing.T) {
	secondary := &fake{allow: true}
	s, _, wg := shadowWith(&fake{err: errors.New("keto down")}, secondary)
	got, err := s.CheckPermission(context.Background(), "Registry", "org", "pushers", "client")
	wg.Wait()
	if err == nil || got {
		t.Fatalf("got %v %v, want an error and no allow", got, err)
	}
	if secondary.calls != 0 {
		t.Errorf("the secondary was asked %d times after a primary failure", secondary.calls)
	}
}

// TestPDPMapsKetoNamesToTheModel checks the request the PDP receives: resource type registry, the relation as the action, the subject as a user, the key as a Bearer token.
func TestPDPMapsKetoNamesToTheModel(t *testing.T) {
	var body map[string]map[string]string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	defer srv.Close()
	p, err := NewPDP(srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := p.CheckPermission(context.Background(), "Registry", "meddleware-org", "pushers", "registry-ci-push")
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
	if auth != "Bearer k" || body["subject"]["type"] != "user" || body["subject"]["id"] != "registry-ci-push" ||
		body["resource"]["type"] != "registry" || body["resource"]["id"] != "meddleware-org" || body["action"]["name"] != "pusher" {
		t.Errorf("request: auth=%q body=%v", auth, body)
	}
}

// TestPDPRefusesWhatTheModelDoesNotKnow: an unknown namespace or relation is an error, not a denial.
func TestPDPRefusesWhatTheModelDoesNotKnow(t *testing.T) {
	p, err := NewPDP("http://127.0.0.1:1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CheckPermission(context.Background(), "Other", "o", "pushers", "c"); err == nil {
		t.Error("unknown namespace accepted")
	}
	if _, err := p.CheckPermission(context.Background(), "Registry", "o", "owners", "c"); err == nil {
		t.Error("unknown relation accepted")
	}
}

// TestPDPFailsClosedWhenUnreachable: nobody listening is an error (the caller answers 503), never an allow.
func TestPDPFailsClosedWhenUnreachable(t *testing.T) {
	p, _ := NewPDP("http://127.0.0.1:1", "")
	if ok, err := p.CheckPermission(context.Background(), "Registry", "o", "pullers", "c"); ok || err == nil {
		t.Errorf("got %v %v", ok, err)
	}
}

// TestMetricsCountTheComparisons: the handler reports agree, differ and error as they happen (the counters are process-wide, so the test compares deltas).
func TestMetricsCountTheComparisons(t *testing.T) {
	read := func() string {
		rec := httptest.NewRecorder()
		MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	before := [3]uint64{shadowAgree.Load(), shadowDiffer.Load(), shadowError.Load()}
	for _, c := range []struct{ p, s *fake }{{&fake{allow: true}, &fake{allow: true}}, {&fake{allow: true}, &fake{}}, {&fake{allow: true}, &fake{err: errors.New("x")}}} {
		sh, _, wg := shadowWith(c.p, c.s)
		_, _ = sh.CheckPermission(context.Background(), "Registry", "o", "pushers", "c")
		wg.Wait()
	}
	if shadowAgree.Load() != before[0]+1 || shadowDiffer.Load() != before[1]+1 || shadowError.Load() != before[2]+1 {
		t.Errorf("counters moved by %d %d %d, want 1 1 1", shadowAgree.Load()-before[0], shadowDiffer.Load()-before[1], shadowError.Load()-before[2])
	}
	out := read()
	for _, want := range []string{`result="agree"`, `result="differ"`, `result="error"`, "# TYPE token_service_authz_shadow_checks_total counter"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}
