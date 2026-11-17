package redact

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// stepKind identifies the kind of a parsed field-path step.
type stepKind uint8

const (
	// stepKey selects a map key (bare or bracket-quoted).
	stepKey stepKind = iota
	// stepIndex selects one array element by position.
	stepIndex
	// stepWildcard selects every array element.
	stepWildcard
	// stepPredicate selects array elements by a field/value equality.
	stepPredicate
)

// pathStep is one parsed element of a field path.
type pathStep struct {
	kind  stepKind
	key   string
	field string
	value string
	index int
}

// parsePath parses a field path into its steps. The grammar is defined in
// ai/method-specs/redaction.md: "." separates segments, a segment is a bare key
// or a bracket-quoted key, optionally followed by [*], [n] or [field=value].
func parsePath(path string) ([]pathStep, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}
	var steps []pathStep
	i := 0
	startOfSegment := true
	afterBracket := false
	for i < len(path) {
		switch path[i] {
		case '.':
			if startOfSegment {
				return nil, fmt.Errorf("empty segment at offset %d", i)
			}
			i++
			startOfSegment = true
			afterBracket = false
		case '[':
			step, n, err := parseBracket(path[i:])
			if err != nil {
				return nil, fmt.Errorf("offset %d: %w", i, err)
			}
			steps = append(steps, step)
			i += n
			if i < len(path) && path[i] != '.' && path[i] != '[' {
				return nil, fmt.Errorf("offset %d: unexpected %q after ']'", i, path[i])
			}
			startOfSegment = false
			afterBracket = true
		default:
			if afterBracket {
				return nil, fmt.Errorf("offset %d: expected '.' before key", i)
			}
			start := i
			for i < len(path) && path[i] != '.' && path[i] != '[' {
				if path[i] == ']' || path[i] == '"' {
					return nil, fmt.Errorf("offset %d: unexpected %q in key", i, path[i])
				}
				i++
			}
			steps = append(steps, pathStep{kind: stepKey, key: path[start:i]})
			startOfSegment = false
		}
	}
	if startOfSegment {
		return nil, errors.New("path must not end with '.'")
	}
	return steps, nil
}

// parseBracket parses a bracket selector at the start of s and returns the step
// and the number of bytes consumed. s must start with '['.
func parseBracket(s string) (pathStep, int, error) {
	if len(s) < 2 {
		return pathStep{}, 0, errors.New("unterminated bracket")
	}
	switch s[1] {
	case '*':
		if len(s) >= 3 && s[2] == ']' {
			return pathStep{kind: stepWildcard}, 3, nil
		}
		return pathStep{}, 0, errors.New("invalid wildcard selector, want [*]")
	case '"':
		end := strings.Index(s[2:], "\"]")
		if end < 0 {
			return pathStep{}, 0, errors.New(`unterminated quoted key, want ["..."]`)
		}
		key := s[2 : 2+end]
		if strings.ContainsRune(key, '"') {
			return pathStep{}, 0, errors.New("unescaped quote in quoted key")
		}
		return pathStep{kind: stepKey, key: key}, 2 + end + 2, nil
	}
	close := strings.IndexByte(s, ']')
	if close < 0 {
		return pathStep{}, 0, errors.New("unterminated bracket")
	}
	content := s[1:close]
	if content == "" {
		return pathStep{}, 0, errors.New("empty bracket selector")
	}
	if isDigits(content) {
		index, err := strconv.Atoi(content)
		if err != nil {
			return pathStep{}, 0, fmt.Errorf("index %q out of range", content)
		}
		return pathStep{kind: stepIndex, index: index}, close + 1, nil
	}
	field, value, ok := strings.Cut(content, "=")
	if !ok {
		return pathStep{}, 0, fmt.Errorf("invalid selector %q: want [*], [n], [\"key\"] or [field=value]", content)
	}
	if field == "" {
		return pathStep{}, 0, errors.New("empty predicate field")
	}
	if strings.ContainsAny(field, `[]"`) {
		return pathStep{}, 0, fmt.Errorf("invalid predicate field %q", field)
	}
	return pathStep{kind: stepPredicate, field: field, value: value}, close + 1, nil
}

// isDigits reports whether s is non-empty and consists only of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
