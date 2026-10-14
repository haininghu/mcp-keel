package config

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a duration expressed in YAML as a Go duration string such as
// "30s" or "10m". The integer scalar 0 is accepted and means zero (used to
// disable the discovery cache).
type Duration time.Duration

// UnmarshalYAML parses a duration string into d.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a string")
	}
	s := strings.TrimSpace(node.Value)
	if s == "" {
		return fmt.Errorf("duration must not be empty")
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(parsed)
	return nil
}

// String returns the canonical Go duration string.
func (d Duration) String() string {
	return time.Duration(d).String()
}
