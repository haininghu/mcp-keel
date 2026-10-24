package policy

import (
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// matches reports whether all of the filter's predicates pass for req. An empty
// filter passes.
func (f *CapabilityFilter) matches(req *Request) bool {
	return f.Labels.matches(req.Labels) && f.Names.matches(req.Name)
}

// matches reports whether the label set satisfies the filter. An empty filter
// passes. When labels are needed but not known the filter fails closed.
func (f LabelFilter) matches(set LabelSet) bool {
	if len(f.Require) == 0 && len(f.Exclude) == 0 {
		return true
	}
	if !set.Known {
		return false
	}
	for _, entry := range f.Exclude {
		if labelMatches(entry, set.Values) {
			return false
		}
	}
	for _, entry := range f.Require {
		if !labelMatches(entry, set.Values) {
			return false
		}
	}
	return true
}

// labelMatches reports whether a single filter entry matches. A bare "key"
// matches key presence; "key=value" matches the exact, case-sensitive value.
func labelMatches(entry string, values map[string]string) bool {
	key, want, hasValue := strings.Cut(entry, "=")
	got, ok := values[key]
	if !ok {
		return false
	}
	if !hasValue {
		return true
	}
	return got == want
}

// matches reports whether the object name satisfies the filter. An empty filter
// passes. When both are set, Exclude wins over Include.
func (f NameFilter) matches(name string) bool {
	if len(f.Include) == 0 && len(f.Exclude) == 0 {
		return true
	}
	for _, pattern := range f.Exclude {
		if doublestar.MatchUnvalidated(pattern, name) {
			return false
		}
	}
	if len(f.Include) == 0 {
		return true
	}
	for _, pattern := range f.Include {
		if doublestar.MatchUnvalidated(pattern, name) {
			return true
		}
	}
	return false
}
