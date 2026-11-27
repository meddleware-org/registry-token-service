// authz.go lets the token service ask one authorization backend, or two in shadow mode (ADR-0016 stage 3, FU-0191).

// Package authz holds the permission check the token service depends on: an interface, its OpenFGA implementation (through the platform's AuthZEN 1.0 client) and a
// shadow wrapper that asks the old backend (Keto) for the answer and the new one (OpenFGA) only to compare, so the migration can be proved before it is switched.
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/meddleware-org/identity-contract/authzen"
)

// Checker answers whether a subject holds a relation on an object. The Keto client implements it; so does PDP.
type Checker interface {
	// CheckPermission returns true when subjectID holds relation on object in namespace. An error means no answer: the caller must fail closed.
	CheckPermission(ctx context.Context, namespace, object, relation, subjectID string) (bool, error)
}

// relations maps a Keto relation name to the OpenFGA relation (which is also the AuthZEN action name) of k8s/base/auth/openfga/model.json in the workspace.
var relations = map[string]string{"pushers": "pusher", "pullers": "puller", "admins": "admin", "listers": "lister"}

// PDP is a Checker backed by an AuthZEN policy decision point (OpenFGA).
type PDP struct {
	// client is the contract's AuthZEN client: it caches decisions (allow 30 s, deny 5 s) and fails closed.
	client *authzen.Client
}

// NewPDP makes a PDP for the store at base (for example http://openfga.auth.svc.cluster.local:8080/stores/<id>), sending key as a Bearer token when it is not empty.
func NewPDP(base, key string) (*PDP, error) {
	var opts []authzen.Option
	if key != "" {
		opts = append(opts, authzen.WithToken(func(context.Context) (string, error) { return key, nil }))
	}
	c, err := authzen.New(base, &http.Client{Timeout: 2 * time.Second}, opts...)
	if err != nil {
		return nil, fmt.Errorf("authzen client: %w", err)
	}
	return &PDP{client: c}, nil
}

// CheckPermission asks the PDP. The namespace `Registry` becomes the resource type `registry`, the Keto relation becomes the action, and the subject is a `user`. A relation the
// model does not know is an error (no answer), never a denial that could be mistaken for a decision.
func (p *PDP) CheckPermission(ctx context.Context, namespace, object, relation, subjectID string) (bool, error) {
	if namespace != "Registry" {
		return false, fmt.Errorf("authz: unknown namespace %q", namespace)
	}
	action, ok := relations[relation]
	if !ok {
		return false, fmt.Errorf("authz: unknown relation %q", relation)
	}
	return p.client.Evaluate(ctx, authzen.Request{
		Subject:  authzen.Entity{Type: "user", ID: subjectID},
		Resource: authzen.Entity{Type: "registry", ID: object},
		Action:   authzen.Action{Name: action},
	})
}

// The shadow comparison counters, exposed by MetricsHandler so the migration's "zero differences for a week" is a number in the metrics store and not a search of rotated logs.
var (
	// shadowAgree counts comparisons where both backends gave the same answer.
	shadowAgree atomic.Uint64
	// shadowDiffer counts comparisons where they disagreed (the only number that must stay zero).
	shadowDiffer atomic.Uint64
	// shadowError counts comparisons where the secondary gave no answer.
	shadowError atomic.Uint64
)

// MetricsHandler serves the shadow counters in the Prometheus text format. It is served on its own port, never on the public one.
func MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "# HELP token_service_authz_shadow_checks_total Shadow comparisons of the permission check against the new backend, by result.\n"+
			"# TYPE token_service_authz_shadow_checks_total counter\n"+
			"token_service_authz_shadow_checks_total{result=\"agree\"} %d\n"+
			"token_service_authz_shadow_checks_total{result=\"differ\"} %d\n"+
			"token_service_authz_shadow_checks_total{result=\"error\"} %d\n", shadowAgree.Load(), shadowDiffer.Load(), shadowError.Load())
	})
}

// Shadow asks Primary for the answer it returns and Secondary only to compare. Secondary can never change, delay or fail a decision: it runs after Primary has
// answered, in its own goroutine with its own deadline, and its errors are only logged.
type Shadow struct {
	// Primary decides.
	Primary Checker
	// Secondary is compared against Primary and otherwise ignored.
	Secondary Checker
	// Log receives one line per difference and per secondary failure (never a token or a secret).
	Log *slog.Logger
	// Timeout bounds the secondary question; zero means two seconds.
	Timeout time.Duration
	// wg lets tests wait for the background comparisons.
	wg waitGroup
}

// waitGroup is the part of sync.WaitGroup the shadow needs, kept as a type so tests can wait on it without exporting a method.
type waitGroup interface {
	Add(int)
	Done()
	Wait()
}

// CheckPermission returns Primary's answer and schedules the comparison with Secondary.
func (s *Shadow) CheckPermission(ctx context.Context, namespace, object, relation, subjectID string) (bool, error) {
	got, err := s.Primary.CheckPermission(ctx, namespace, object, relation, subjectID)
	if err != nil {
		// No primary answer: nothing to compare, and the caller fails closed as before.
		return false, err
	}
	s.compare(namespace, object, relation, subjectID, got)
	return got, nil
}

// compare asks Secondary in the background and logs a difference or a failure.
func (s *Shadow) compare(namespace, object, relation, subjectID string, want bool) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	if s.wg != nil {
		s.wg.Add(1)
	}
	go func() {
		if s.wg != nil {
			defer s.wg.Done()
		}
		// The request's context ends with the response; the comparison has its own.
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		other, err := s.Secondary.CheckPermission(ctx, namespace, object, relation, subjectID)
		switch {
		case err != nil:
			shadowError.Add(1)
			s.Log.Warn("authz shadow: no answer from the new backend", "namespace", namespace, "object", object, "relation", relation, "subject", subjectID)
		case other != want:
			shadowDiffer.Add(1)
			s.Log.Warn("authz shadow: DIFFERENCE", "namespace", namespace, "object", object, "relation", relation, "subject", subjectID, "keto", want, "openfga", other)
		default:
			shadowAgree.Add(1)
		}
	}()
}
