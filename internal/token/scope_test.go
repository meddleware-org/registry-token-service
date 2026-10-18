package token

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseScope(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []ScopeItem
	}{
		{"empty", "", nil},
		{
			"single repository with two actions",
			"repository:meddleware-org/foo:push,pull",
			[]ScopeItem{{Type: "repository", Name: "meddleware-org/foo", Actions: []string{"push", "pull"}}},
		},
		{
			"multiple space-separated scopes",
			"repository:a/b:pull registry:catalog:*",
			[]ScopeItem{
				{Type: "repository", Name: "a/b", Actions: []string{"pull"}},
				{Type: "registry", Name: "catalog", Actions: []string{"*"}},
			},
		},
		{"malformed missing action segment dropped", "repository:a/b", nil},
		{"empty actions dropped", "repository:a/b:", nil},
		{"empty action tokens filtered", "repository:a/b:,pull,", []ScopeItem{{Type: "repository", Name: "a/b", Actions: []string{"pull"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseScope(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseScope(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestFilterActions(t *testing.T) {
	item := ScopeItem{Type: "repository", Name: "a/b", Actions: []string{"push", "pull"}}

	t.Run("intersects requested with allowed", func(t *testing.T) {
		got := item.FilterActions([]string{"pull"})
		if got == nil || !reflect.DeepEqual(got.Actions, []string{"pull"}) {
			t.Fatalf("FilterActions(pull) = %+v, want actions [pull]", got)
		}
	})

	t.Run("empty intersection returns nil (no scope granted)", func(t *testing.T) {
		if got := item.FilterActions([]string{"delete"}); got != nil {
			t.Fatalf("FilterActions(delete) = %+v, want nil", got)
		}
	})

	t.Run("nil allowed returns nil", func(t *testing.T) {
		if got := item.FilterActions(nil); got != nil {
			t.Fatalf("FilterActions(nil) = %+v, want nil", got)
		}
	})

	t.Run("preserves type and name", func(t *testing.T) {
		got := item.FilterActions([]string{"push", "pull"})
		if got == nil || got.Type != "repository" || got.Name != "a/b" {
			t.Fatalf("FilterActions kept wrong type/name: %+v", got)
		}
	})
}

func TestValidRepositoryName(t *testing.T) {
	valid := []string{"app", "org/app", "meddleware-org/registry-auth-proxy", "a.b/c_d/e__f/g--h", "org/a1", strings.Repeat("a", MaxNameLength)}
	for _, n := range valid {
		if !ValidRepositoryName(n) {
			t.Errorf("%q should be a valid repository name", n)
		}
	}
	invalid := []string{
		"", "Org/App", "org//app", "/org", "org/", "org/app/", "-org/app", "org/app-", "org/.app", "org/app.", "a/../b",
		"org/app#pushers", "org/app:tag", "org app", "org/ap\np", "org/app\x00", "org/ä", "org/a___b", strings.Repeat("a", MaxNameLength+1),
	}
	for _, n := range invalid {
		if ValidRepositoryName(n) {
			t.Errorf("%q must not be a valid repository name (it would become a Keto object)", n)
		}
	}
}

func TestParseScopeParams(t *testing.T) {
	t.Run("every repeated parameter is evaluated, in order", func(t *testing.T) {
		got, err := ParseScopeParams([]string{"repository:a/one:push,pull", "repository:b/two:pull", "registry:catalog:*"})
		if err != nil {
			t.Fatal(err)
		}
		want := []ScopeItem{
			{Type: "repository", Name: "a/one", Actions: []string{"push", "pull"}},
			{Type: "repository", Name: "b/two", Actions: []string{"pull"}},
			{Type: "registry", Name: "catalog", Actions: []string{"*"}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a repeated parameter may itself hold several space-separated entries", func(t *testing.T) {
		got, err := ParseScopeParams([]string{"repository:a/one:pull repository:a/two:pull", "repository:b/three:pull"})
		if err != nil || len(got) != 3 {
			t.Fatalf("got %+v, %v; want 3 items", got, err)
		}
	})

	t.Run("no parameter, empty and malformed values give no items and no error", func(t *testing.T) {
		for _, in := range [][]string{nil, {}, {""}, {"", ""}, {"repository:a/b"}} {
			if got, err := ParseScopeParams(in); err != nil || len(got) != 0 {
				t.Errorf("ParseScopeParams(%q) = %+v, %v; want nothing", in, got, err)
			}
		}
	})

	t.Run("the entry bound spans all parameters", func(t *testing.T) {
		// MaxScopeItems entries pass however they are split; one more fails.
		atLimit := make([]string, MaxScopeItems)
		for i := range atLimit {
			atLimit[i] = "repository:org/app:pull"
		}
		if got, err := ParseScopeParams(atLimit); err != nil || len(got) != MaxScopeItems {
			t.Fatalf("%d entries: %d items, %v", MaxScopeItems, len(got), err)
		}
		if _, err := ParseScopeParams(append(atLimit, "repository:org/app:pull")); err != ErrTooManyScopes {
			t.Errorf("%d entries: err = %v, want ErrTooManyScopes", MaxScopeItems+1, err)
		}
	})

	t.Run("the byte bound spans all parameters", func(t *testing.T) {
		half := strings.Repeat("a", MaxScopeBytes/2)
		if _, err := ParseScopeParams([]string{half, half}); err != nil {
			t.Fatalf("exactly %d bytes: %v", MaxScopeBytes, err)
		}
		if _, err := ParseScopeParams([]string{half, half, "x"}); err != ErrScopeTooLong {
			t.Errorf("%d bytes over several parameters: err = %v, want ErrScopeTooLong", MaxScopeBytes+1, err)
		}
		many := make([]string, MaxScopeBytes+1)
		for i := range many {
			many[i] = "x"
		}
		if _, err := ParseScopeParams(many); err != ErrScopeTooLong {
			t.Errorf("%d one-byte parameters: err = %v, want ErrScopeTooLong", len(many), err)
		}
	})
}
