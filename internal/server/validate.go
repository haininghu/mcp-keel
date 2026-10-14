package server

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Input bounds. Resource identifiers and context names are DNS-ish strings; the
// label selector is a free-form API-server query.
const (
	maxIdentifierBytes    = 253
	maxLabelSelectorBytes = 4096
)

// validateText rejects an empty or overlong text argument and any control
// character, which prevents log injection through echoed input.
func validateText(field, value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds the %d byte limit", field, len(value))
	}
	return rejectControlChars(field, value)
}

// rejectControlChars rejects NUL, C0 controls and DEL.
func rejectControlChars(field, value string) error {
	for _, r := range value {
		if r == 0 || r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains control characters", field)
		}
	}
	return nil
}

// validateNamespace validates a namespace as a DNS-1123 label.
func validateNamespace(namespace string) error {
	if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
		return fmt.Errorf("invalid namespace %q", namespace)
	}
	return nil
}

// validateName validates an object name as a DNS-1123 subdomain. This is the
// loosest Kubernetes name form; resource-specific tightening is left to the API
// server.
func validateName(name string) error {
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("invalid name %q", name)
	}
	return nil
}

// validateLabelSelector bounds a caller-supplied label selector and rejects
// control characters. It is passed to the API server unchanged.
func validateLabelSelector(selector string) error {
	if selector == "" {
		return nil
	}
	if len(selector) > maxLabelSelectorBytes {
		return fmt.Errorf("labelSelector exceeds the %d byte limit", maxLabelSelectorBytes)
	}
	return rejectControlChars("labelSelector", selector)
}

// clampListLimit applies the caller's limit, defaulting it to the configured
// server.max_list_items and never exceeding it.
func (s *Server) clampListLimit(requested int) int {
	limit := requested
	if limit <= 0 {
		limit = s.cfg.Server.MaxListItems
	}
	if limit > s.cfg.Server.MaxListItems {
		limit = s.cfg.Server.MaxListItems
	}
	return limit
}
