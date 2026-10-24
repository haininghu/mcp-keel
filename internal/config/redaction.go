package config

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/haininghu/mcp-keel/internal/policy"
)

// Field redaction actions, the accepted values of FieldRedaction.Action.
const (
	fieldActionRemove  = "remove"
	fieldActionReplace = "replace"
)

// RedactionConfig is one configured content-redaction rule (ADR 0015). All match
// dimensions are optional: an omitted dimension imposes no constraint and every
// present dimension must match (AND). A rule must carry at least one action.
type RedactionConfig struct {
	// Resources lists canonical resource identifiers
	// ("[group/]resource[/subresource]", ADR 0012). There is no "*"; an
	// unresolvable or ambiguous resource is skipped when the rule is applied.
	Resources []string `yaml:"resources"`
	// Namespaces is a list of doublestar globs; the literal "" selects
	// cluster-scoped resources.
	Namespaces []string `yaml:"namespaces"`
	// Names is a list of doublestar globs matched against metadata.name.
	Names []string `yaml:"names"`
	// Labels is the optional label filter, evaluated as in the policy rules.
	Labels policy.LabelFilter `yaml:"labels"`
	// Fields lists the structural field operations.
	Fields []FieldRedaction `yaml:"fields"`
	// Replace lists the textual replacements.
	Replace []ReplaceRedaction `yaml:"replace"`
}

// FieldRedaction is a structural field operation: remove the matched field or
// replace its terminal string value with the marker.
type FieldRedaction struct {
	// Path is the field path; it must not be empty. Its grammar is validated by
	// the redaction engine, not at load.
	Path string `yaml:"path"`
	// Action is "remove" or "replace"; it is required.
	Action string `yaml:"action"`
	// Marker overrides the default marker; when set it must not be empty.
	Marker *string `yaml:"marker"`
}

// ReplaceRedaction is a textual replacement over string values. Exactly one of
// Text or Pattern must be set and non-empty.
type ReplaceRedaction struct {
	// Text is a literal substring to replace.
	Text string `yaml:"text"`
	// Pattern is an RE2 regular expression, compiled at load.
	Pattern string `yaml:"pattern"`
	// Marker overrides the default marker; when set it must not be empty.
	Marker *string `yaml:"marker"`
}

// validate fails closed on an invalid redaction rule, naming the offending path.
func (r *RedactionConfig) validate() error {
	for i, resource := range r.Resources {
		if err := validateResourceSyntax(resource, false); err != nil {
			return fmt.Errorf("resources[%d]: %w", i, err)
		}
	}
	for i, namespace := range r.Namespaces {
		if namespace == "" {
			continue
		}
		if !doublestar.ValidatePattern(namespace) {
			return fmt.Errorf("namespaces[%d]: invalid glob %q", i, namespace)
		}
	}
	for i, name := range r.Names {
		if !doublestar.ValidatePattern(name) {
			return fmt.Errorf("names[%d]: invalid glob %q", i, name)
		}
	}
	if err := validateLabelFilter(r.Labels); err != nil {
		return fmt.Errorf("labels: %w", err)
	}
	if len(r.Fields) == 0 && len(r.Replace) == 0 {
		return errors.New("rule must have at least one action (fields or replace)")
	}
	for i := range r.Fields {
		if err := r.Fields[i].validate(); err != nil {
			return fmt.Errorf("fields[%d]: %w", i, err)
		}
	}
	for i := range r.Replace {
		if err := r.Replace[i].validate(); err != nil {
			return fmt.Errorf("replace[%d]: %w", i, err)
		}
	}
	return nil
}

func (f *FieldRedaction) validate() error {
	if f.Path == "" {
		return errors.New("path: must not be empty")
	}
	switch f.Action {
	case fieldActionRemove, fieldActionReplace:
	default:
		return fmt.Errorf("action: must be remove or replace, got %q", f.Action)
	}
	if f.Marker != nil && *f.Marker == "" {
		return errors.New("marker: must not be empty when set")
	}
	return nil
}

func (r *ReplaceRedaction) validate() error {
	switch {
	case r.Text != "" && r.Pattern != "":
		return errors.New("exactly one of text or pattern is required, not both")
	case r.Text == "" && r.Pattern == "":
		return errors.New("exactly one non-empty text or pattern is required")
	}
	if r.Pattern != "" {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("pattern: invalid RE2 regular expression: %w", err)
		}
	}
	if r.Marker != nil && *r.Marker == "" {
		return errors.New("marker: must not be empty when set")
	}
	return nil
}
