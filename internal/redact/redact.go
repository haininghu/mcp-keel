// Package redact applies configured content-redaction rules to tool results
// (ADR 0015). It is a pure, post-authorization transformation: it never
// authorizes or denies and it performs no I/O.
package redact

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/haininghu/mcp-keel/internal/policy"
)

// DefaultMarker is the marker inserted when an operation sets no marker of its
// own.
const DefaultMarker = "[REDACTED]"

// Hard caps for a redaction walk. A breach fails closed: the object is never
// returned unredacted.
const (
	// MaxWorkBytes bounds the total bytes of the string values visited.
	MaxWorkBytes = 8 << 20
	// MaxDepth bounds the nesting depth of the walked JSON value. The root
	// object is at depth 0.
	MaxDepth = 64
)

// ErrCapBreached reports that a redaction walk exceeded MaxWorkBytes or
// MaxDepth. Callers must treat the object as unreturnable.
var ErrCapBreached = errors.New("redaction cap breached")

// Action is a structural field operation.
type Action string

const (
	// ActionRemove deletes the selected field or array element.
	ActionRemove Action = "remove"
	// ActionReplace overwrites the selected terminal string with the marker.
	ActionReplace Action = "replace"
)

// FieldOp is one structural field operation.
type FieldOp struct {
	// Path is the field path; its grammar is validated by Build.
	Path string
	// Action is ActionRemove or ActionReplace.
	Action Action
	// Marker overrides DefaultMarker; empty selects DefaultMarker.
	Marker string
}

// ReplaceOp is one textual replacement over string values. Exactly one of Text
// and Pattern must be non-empty.
type ReplaceOp struct {
	// Text is a literal substring.
	Text string
	// Pattern is an RE2 regular expression.
	Pattern string
	// Marker overrides DefaultMarker; empty selects DefaultMarker.
	Marker string
}

// Rule is one configured content-redaction rule. All match dimensions are
// optional: an omitted dimension imposes no constraint and every present
// dimension must match (AND).
type Rule struct {
	// Resources lists canonical resources; empty matches every resource.
	Resources []policy.Resource
	// Namespaces lists doublestar globs; the literal "" selects cluster-scoped
	// objects.
	Namespaces []string
	// Names lists doublestar globs matched against the object name.
	Names []string
	// Labels is the optional label filter, evaluated as in the policy.
	Labels policy.LabelFilter
	// Fields lists the structural field operations.
	Fields []FieldOp
	// Replace lists the textual replacements.
	Replace []ReplaceOp
}

// Match describes the object a rule is matched against.
type Match struct {
	// Resource is the canonical resource of the object.
	Resource policy.Resource
	// Namespace is the object's namespace.
	Namespace string
	// Namespaced reports whether the resource is namespaced.
	Namespaced bool
	// Name is the object name.
	Name string
	// Labels is the object's label set.
	Labels policy.LabelSet
}

// Engine applies a set of redaction rules. It is immutable after Build and safe
// for concurrent use.
type Engine struct {
	rules []compiledRule
}

// compiledRule is a validated Rule with parsed paths and compiled patterns.
type compiledRule struct {
	rule    Rule
	fields  []compiledField
	replace []compiledReplace
}

// compiledField is a validated FieldOp.
type compiledField struct {
	steps  []pathStep
	action Action
	marker string
}

// compiledReplace is a validated ReplaceOp. Exactly one of text and re is set.
type compiledReplace struct {
	text   string
	re     *regexp.Regexp
	marker string
}

// Build validates rules and compiles them into an Engine. Rules are kept in
// configuration order.
func Build(rules []Rule) (*Engine, error) {
	engine := &Engine{rules: make([]compiledRule, 0, len(rules))}
	for i := range rules {
		rule, err := compileRule(&rules[i])
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		engine.rules = append(engine.rules, rule)
	}
	return engine, nil
}

// ValidatePath reports whether path conforms to the field-path grammar.
func ValidatePath(path string) error {
	_, err := parsePath(path)
	return err
}

// ApplyObject returns a deep copy of obj with every matching rule applied. The
// input is never mutated. Fields run first (rule order, then list order),
// followed by every textual replacement. On ErrCapBreached the returned object
// is nil.
func (e *Engine) ApplyObject(obj map[string]any, m Match) (map[string]any, error) {
	matched := e.matchingRules(m)
	out, err := copyObject(obj)
	if err != nil {
		return nil, err
	}
	if len(matched) == 0 {
		return out, nil
	}
	for _, index := range matched {
		rule := &e.rules[index]
		for i := range rule.fields {
			op := &rule.fields[i]
			applyPath(out, op.steps, op.action, op.marker)
		}
	}
	var replacements []compiledReplace
	for _, index := range matched {
		replacements = append(replacements, e.rules[index].replace...)
	}
	state := walkState{replacements: replacements}
	if _, err := state.walk(out, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// ApplyText applies every matching textual replacement to s and returns the
// result. Bytes outside matches, including line endings, are preserved.
func (e *Engine) ApplyText(s string, m Match) (string, error) {
	matched := e.matchingRules(m)
	var replacements []compiledReplace
	for _, index := range matched {
		replacements = append(replacements, e.rules[index].replace...)
	}
	if len(replacements) == 0 {
		return s, nil
	}
	if len(s) > MaxWorkBytes {
		return "", fmt.Errorf("%w: work bytes exceed %d", ErrCapBreached, MaxWorkBytes)
	}
	return applyReplacements(s, replacements), nil
}

// matchingRules returns the indexes of all rules that match m, in configuration
// order.
func (e *Engine) matchingRules(m Match) []int {
	var matched []int
	for i := range e.rules {
		if e.rules[i].matches(m) {
			matched = append(matched, i)
		}
	}
	return matched
}

// matches reports whether every present match dimension matches m.
func (r *compiledRule) matches(m Match) bool {
	if len(r.rule.Resources) > 0 && !slices.Contains(r.rule.Resources, m.Resource) {
		return false
	}
	if len(r.rule.Namespaces) > 0 && !matchNamespace(r.rule.Namespaces, m.Namespace, m.Namespaced) {
		return false
	}
	if len(r.rule.Names) > 0 && !matchAnyGlob(r.rule.Names, m.Name) {
		return false
	}
	return r.rule.Labels.Matches(m.Labels)
}

// matchNamespace reports whether namespace matches one of the patterns. The
// literal "" matches only a cluster-scoped object and never a namespaced one; a
// glob never matches a cluster-scoped object.
func matchNamespace(patterns []string, namespace string, namespaced bool) bool {
	if !namespaced {
		return slices.Contains(patterns, "")
	}
	// A namespaced object always has a namespace; an empty one fails closed so
	// no wildcard can ever match it (the policy uses the same rule).
	if namespace == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if doublestar.MatchUnvalidated(pattern, namespace) {
			return true
		}
	}
	return false
}

// matchAnyGlob reports whether name matches at least one pattern.
func matchAnyGlob(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if doublestar.MatchUnvalidated(pattern, name) {
			return true
		}
	}
	return false
}

// compileRule validates and compiles one rule.
func compileRule(rule *Rule) (compiledRule, error) {
	compiled := compiledRule{
		rule: Rule{
			Resources:  slices.Clone(rule.Resources),
			Namespaces: slices.Clone(rule.Namespaces),
			Names:      slices.Clone(rule.Names),
			Labels: policy.LabelFilter{
				Require: slices.Clone(rule.Labels.Require),
				Exclude: slices.Clone(rule.Labels.Exclude),
			},
		},
	}
	for i, namespace := range rule.Namespaces {
		if namespace == "" {
			continue
		}
		if !doublestar.ValidatePattern(namespace) {
			return compiledRule{}, fmt.Errorf("namespaces[%d]: invalid glob %q", i, namespace)
		}
	}
	for i, name := range rule.Names {
		if !doublestar.ValidatePattern(name) {
			return compiledRule{}, fmt.Errorf("names[%d]: invalid glob %q", i, name)
		}
	}
	for i := range rule.Fields {
		field, err := compileField(&rule.Fields[i])
		if err != nil {
			return compiledRule{}, fmt.Errorf("fields[%d]: %w", i, err)
		}
		compiled.fields = append(compiled.fields, field)
	}
	for i := range rule.Replace {
		replace, err := compileReplace(&rule.Replace[i])
		if err != nil {
			return compiledRule{}, fmt.Errorf("replace[%d]: %w", i, err)
		}
		compiled.replace = append(compiled.replace, replace)
	}
	return compiled, nil
}

// compileField validates and compiles one field operation.
func compileField(op *FieldOp) (compiledField, error) {
	if op.Path == "" {
		return compiledField{}, errors.New("path must not be empty")
	}
	steps, err := parsePath(op.Path)
	if err != nil {
		return compiledField{}, fmt.Errorf("path %q: %w", op.Path, err)
	}
	switch op.Action {
	case ActionRemove, ActionReplace:
	default:
		return compiledField{}, fmt.Errorf("action must be %q or %q, got %q", ActionRemove, ActionReplace, op.Action)
	}
	return compiledField{steps: steps, action: op.Action, marker: markerOrDefault(op.Marker)}, nil
}

// compileReplace validates and compiles one textual replacement.
func compileReplace(op *ReplaceOp) (compiledReplace, error) {
	switch {
	case op.Text != "" && op.Pattern != "":
		return compiledReplace{}, errors.New("exactly one of text or pattern is required, not both")
	case op.Text == "" && op.Pattern == "":
		return compiledReplace{}, errors.New("exactly one non-empty text or pattern is required")
	}
	compiled := compiledReplace{marker: markerOrDefault(op.Marker)}
	if op.Text != "" {
		compiled.text = op.Text
		return compiled, nil
	}
	re, err := regexp.Compile(op.Pattern)
	if err != nil {
		return compiledReplace{}, fmt.Errorf("invalid RE2 pattern: %w", err)
	}
	compiled.re = re
	return compiled, nil
}

// markerOrDefault returns marker, or DefaultMarker when marker is empty.
func markerOrDefault(marker string) string {
	if marker == "" {
		return DefaultMarker
	}
	return marker
}

// copyObject deep-copies a JSON object. A depth breach fails closed.
func copyObject(obj map[string]any) (map[string]any, error) {
	if obj == nil {
		return nil, nil
	}
	value, err := deepCopy(obj, 0)
	if err != nil {
		return nil, err
	}
	out, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("object is not a JSON map")
	}
	return out, nil
}

// deepCopy copies a JSON value (maps, slices and scalars). A depth breach fails
// closed.
func deepCopy(value any, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("%w: depth exceeds %d", ErrCapBreached, MaxDepth)
	}
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			copied, err := deepCopy(child, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = copied
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i := range v {
			copied, err := deepCopy(v[i], depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = copied
		}
		return out, nil
	default:
		return value, nil
	}
}

// walkState carries the replacement list and the accumulated work of one walk.
type walkState struct {
	replacements []compiledReplace
	bytes        int
}

// walk visits every JSON value, counts the bytes of string values and replaces
// matching text. Maps and slices are edited in place.
func (s *walkState) walk(value any, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("%w: depth exceeds %d", ErrCapBreached, MaxDepth)
	}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			walked, err := s.walk(child, depth+1)
			if err != nil {
				return nil, err
			}
			v[key] = walked
		}
		return v, nil
	case []any:
		for i := range v {
			walked, err := s.walk(v[i], depth+1)
			if err != nil {
				return nil, err
			}
			v[i] = walked
		}
		return v, nil
	case string:
		s.bytes += len(v)
		if s.bytes > MaxWorkBytes {
			return nil, fmt.Errorf("%w: work bytes exceed %d", ErrCapBreached, MaxWorkBytes)
		}
		if len(s.replacements) == 0 {
			return v, nil
		}
		return applyReplacements(v, s.replacements), nil
	default:
		return value, nil
	}
}

// span is one replacement match: the byte range [start, end) attributed to the
// replace operation with the given configuration index.
type span struct {
	start int
	end   int
	rule  int
}

// applyReplacements computes a cascade-free interval union over s. All matches
// are found in the original string; a marker inserted by one match is never
// scanned again. For overlapping matches, the marker of the first matching
// rule wins.
func applyReplacements(s string, replacements []compiledReplace) string {
	var spans []span
	for i := range replacements {
		op := &replacements[i]
		if op.re != nil {
			for _, loc := range op.re.FindAllStringIndex(s, -1) {
				if loc[1] > loc[0] {
					spans = append(spans, span{start: loc[0], end: loc[1], rule: i})
				}
			}
			continue
		}
		for pos := 0; pos+len(op.text) <= len(s); {
			index := strings.Index(s[pos:], op.text)
			if index < 0 {
				break
			}
			start := pos + index
			spans = append(spans, span{start: start, end: start + len(op.text), rule: i})
			pos = start + len(op.text)
		}
	}
	if len(spans) == 0 {
		return s
	}
	slices.SortFunc(spans, func(a, b span) int {
		if a.start != b.start {
			return cmp.Compare(a.start, b.start)
		}
		return cmp.Compare(a.rule, b.rule)
	})
	bounds := make([]int, 0, 2*len(spans))
	for _, match := range spans {
		bounds = append(bounds, match.start, match.end)
	}
	slices.Sort(bounds)
	bounds = slices.Compact(bounds)

	var builder strings.Builder
	builder.Grow(len(s))
	position := 0
	added := 0
	active := make([]span, 0, len(spans))
	lastRule := -2
	for i := 0; i+1 < len(bounds); i++ {
		start, end := bounds[i], bounds[i+1]
		for added < len(spans) && spans[added].start <= start {
			active = append(active, spans[added])
			added++
		}
		kept := active[:0]
		for _, match := range active {
			if match.end > start {
				kept = append(kept, match)
			}
		}
		active = kept
		rule := -1
		for _, match := range active {
			if match.end >= end && (rule < 0 || match.rule < rule) {
				rule = match.rule
			}
		}
		if start > position {
			builder.WriteString(s[position:start])
			lastRule = -1
		}
		if rule < 0 {
			builder.WriteString(s[start:end])
			lastRule = -1
		} else if rule != lastRule {
			builder.WriteString(replacements[rule].marker)
			lastRule = rule
		}
		position = end
	}
	if position < len(s) {
		builder.WriteString(s[position:])
	}
	return builder.String()
}

// applyPath applies one field operation to node and returns the possibly
// rewritten node. Maps are edited in place; a removed array element requires the
// rewritten slice to be returned to its parent.
func applyPath(node any, steps []pathStep, action Action, marker string) any {
	if len(steps) == 0 {
		return node
	}
	step := steps[0]
	last := len(steps) == 1
	switch step.kind {
	case stepKey:
		m, ok := node.(map[string]any)
		if !ok {
			return node
		}
		if last {
			if action == ActionRemove {
				delete(m, step.key)
				return m
			}
			if _, ok := m[step.key].(string); ok {
				m[step.key] = marker
			}
			return m
		}
		child, ok := m[step.key]
		if !ok {
			return m
		}
		m[step.key] = applyPath(child, steps[1:], action, marker)
		return m
	case stepIndex:
		array, ok := node.([]any)
		if !ok || step.index < 0 || step.index >= len(array) {
			return node
		}
		if last {
			if action == ActionRemove {
				return slices.Delete(array, step.index, step.index+1)
			}
			if _, ok := array[step.index].(string); ok {
				array[step.index] = marker
			}
			return array
		}
		array[step.index] = applyPath(array[step.index], steps[1:], action, marker)
		return array
	case stepWildcard:
		array, ok := node.([]any)
		if !ok {
			return node
		}
		if last {
			if action == ActionRemove {
				return []any{}
			}
			for i := range array {
				if _, ok := array[i].(string); ok {
					array[i] = marker
				}
			}
			return array
		}
		for i := range array {
			array[i] = applyPath(array[i], steps[1:], action, marker)
		}
		return array
	case stepPredicate:
		array, ok := node.([]any)
		if !ok {
			return node
		}
		if last && action == ActionRemove {
			kept := make([]any, 0, len(array))
			for i := range array {
				if predicateMatches(array[i], step) {
					continue
				}
				kept = append(kept, array[i])
			}
			return kept
		}
		for i := range array {
			if !predicateMatches(array[i], step) {
				continue
			}
			array[i] = applyPath(array[i], steps[1:], action, marker)
		}
		return array
	default:
		return node
	}
}

// predicateMatches reports whether node is a map whose field equals the
// predicate value as an exact, case-sensitive string.
func predicateMatches(node any, step pathStep) bool {
	m, ok := node.(map[string]any)
	if !ok {
		return false
	}
	value, ok := m[step.field].(string)
	return ok && value == step.value
}
