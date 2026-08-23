// Package token provides JWT issuance and scope parsing for the Distribution
// registry token auth specification.
package token

import (
	"strings"
)

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
