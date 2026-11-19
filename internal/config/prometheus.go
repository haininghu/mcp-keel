package config

import (
	"fmt"
	"regexp"
)

// prometheusNameRE matches a Prometheus datasource name: a lowercase identifier
// of at most 253 bytes, allowing separators '-', '.' and '_'. The name is
// addressed by policy name filters and must never be a K8s path segment, so any
// otherwise-ambiguous punctuation is deliberately excluded.
var prometheusNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9._]*[a-z0-9])?$`)

// PrometheusDatasource is one configured in-cluster Prometheus datasource
// (ADR 0017). The server reaches it through the Kubernetes service proxy; the
// namespace, service and port are therefore configuration, never tool input.
type PrometheusDatasource struct {
	// Name is the datasource identifier, unique within the provider. It is the
	// `name` dimension of the policy request and of `names` filters.
	Name string `yaml:"name"`
	// Namespace is the namespace of the Service, a DNS-1123 label.
	Namespace string `yaml:"namespace"`
	// Service is the Service name, a DNS-1123 subdomain.
	Service string `yaml:"service"`
	// Port is the numeric Service port in 1..65535.
	Port int `yaml:"port"`
}

// validate fails closed on an invalid datasource, naming the offending field.
func (d *PrometheusDatasource) validate() error {
	if d.Name == "" || len(d.Name) > 253 || !prometheusNameRE.MatchString(d.Name) {
		return fmt.Errorf("name: must be a lowercase identifier of at most 253 bytes, got %q", d.Name)
	}
	if !validDNSLabel(d.Namespace) {
		return fmt.Errorf("namespace: %q is not a valid DNS-1123 label", d.Namespace)
	}
	if !validDNSSubdomain(d.Service) {
		return fmt.Errorf("service: %q is not a valid DNS-1123 subdomain", d.Service)
	}
	if d.Port < 1 || d.Port > 65535 {
		return fmt.Errorf("port: must be in 1..65535, got %d", d.Port)
	}
	return nil
}

// validDNSLabel reports whether s is a valid DNS-1123 label.
func validDNSLabel(s string) bool {
	return s != "" && len(s) <= 63 && dnsLabelRE.MatchString(s)
}
