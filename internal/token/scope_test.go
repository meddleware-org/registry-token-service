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
