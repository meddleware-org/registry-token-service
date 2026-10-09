// Package token provides JWT issuance and scope parsing for the Distribution
// registry token auth specification.
package token

import (
	"regexp"
	"strings"
)

// Limits on a token request. A Docker client asks for a handful of scopes; each requested action costs up
// to two sequential Keto checks, so an unbounded request would let any credential holder multiply its work
// at the authorization service.
const (
	// MaxScopeBytes bounds the raw `scope` query value.
	MaxScopeBytes = 4096
	// MaxScopeItems bounds the number of scope entries in one request.
	MaxScopeItems = 16
	// MaxNameLength is the Distribution limit on a repository name.
	MaxNameLength = 255
)

// repositoryName is the Distribution repository-name grammar: lower-case path components of
// alphanumerics joined by `.`, `_`, `__` or runs of `-`, separated by `/`.
var repositoryName = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// ValidRepositoryName reports whether name is a well-formed Distribution repository name. A name that is
// not one never reaches the authorization service as a Keto object.
func ValidRepositoryName(name string) bool {
	return len(name) <= MaxNameLength && repositoryName.MatchString(name)
}

// ScopeItem represents a single parsed scope from the Docker token request
// (e.g. "repository:myorg/myimage:push,pull").
type ScopeItem struct {
	// Type is the resource type, typically "repository".
	Type string
	// Name is the resource name, e.g. "myorg/myimage".
	Name string
	// Actions is the requested set of actions, e.g. ["push", "pull"].
	Actions []string
}

// ParseScope parses one or more space-separated scope strings from the Docker
// token request query parameter into ScopeItems.
// Invalid or empty entries are silently dropped.
func ParseScope(raw string) []ScopeItem {
	var items []ScopeItem
	for _, part := range strings.Fields(raw) {
		segments := strings.SplitN(part, ":", 3)
		if len(segments) != 3 {
			continue
		}
		actions := strings.Split(segments[2], ",")
		nonEmpty := actions[:0]
		for _, a := range actions {
			if a != "" {
				nonEmpty = append(nonEmpty, a)
			}
		}
		if len(nonEmpty) == 0 {
			continue
		}
		items = append(items, ScopeItem{
			Type:    segments[0],
			Name:    segments[1],
			Actions: nonEmpty,
		})
	}
	return items
}

// FilterActions returns a copy of item with only the actions present in allowed.
// Returns nil if no actions survive the filter.
func (item ScopeItem) FilterActions(allowed []string) *ScopeItem {
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	var keep []string
	for _, a := range item.Actions {
		if _, ok := set[a]; ok {
			keep = append(keep, a)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return &ScopeItem{Type: item.Type, Name: item.Name, Actions: keep}
}
