// Package config loads and validates the mcp-keel YAML configuration.
//
// Parsing is strict: unknown keys are rejected (KnownFields), every rule,
// capability and filter is validated at load, and validation fails closed so a
// misconfiguration can never silently grant access. The package depends only on
// the standard library, doublestar and internal/policy; it performs no
// Kubernetes discovery or canonicalisation. A capability resource is kept as the
// string that was written and is canonicalised later per (provider, context) by
// the kube layer (ADR 0012).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"github.com/hvo/mcp-keel/internal/policy"
)

const (
	defaultVersion              = 1
	defaultName                 = "mcp-keel"
	defaultLogLevel             = LogLevelInfo
	defaultRequestTimeout       = 30 * time.Second
	defaultDiscoveryTimeout     = 10 * time.Second
	defaultDiscoveryCacheTTL    = 10 * time.Minute
	defaultQPS                  = 20.0
	defaultBurst                = 50
	defaultMaxListItems         = 500
	defaultMaxObjectBytes       = 1 << 20
	defaultMaxResponseBytes     = 8 << 20
	defaultNamespaceMarkerLabel = "mcp-keel.io/noai"

	// maxListItemsLimit is the hard upper bound for server.max_list_items.
	maxListItemsLimit = 1000
)

// LogLevel is a server log verbosity level.
type LogLevel string

const (
	// LogLevelDebug enables debug logging.
	LogLevelDebug LogLevel = "debug"
	// LogLevelInfo enables informational logging (the default).
	LogLevelInfo LogLevel = "info"
	// LogLevelWarn enables warning and error logging.
	LogLevelWarn LogLevel = "warn"
	// LogLevelError enables error logging only.
	LogLevelError LogLevel = "error"
)

// Config is a fully defaulted and validated configuration.
type Config struct {
	// Version is the configuration schema version; it must be 1.
	Version int
	// Server holds the server-wide defaults.
	Server ServerConfig
	// Providers holds the ordered list of configured clusters.
	Providers []ProviderConfig
}

// ServerConfig holds the server-wide settings that providers inherit.
type ServerConfig struct {
	// Name is the MCP server name.
	Name string
	// LogLevel is the server log verbosity.
	LogLevel LogLevel
	// RequestTimeout bounds each cluster request.
	RequestTimeout Duration
	// DiscoveryTimeout bounds each discovery call.
	DiscoveryTimeout Duration
	// DiscoveryCacheTTL is the discovery cache lifetime; 0 disables caching.
	DiscoveryCacheTTL Duration
	// QPS is the client-go rate limit.
	QPS float64
	// Burst is the client-go burst limit.
	Burst int
	// MaxListItems is the hard cap on items returned by a list.
	MaxListItems int
	// MaxObjectBytes is the maximum size of a single object before reduction.
	MaxObjectBytes int
	// MaxResponseBytes bounds the whole serialized response.
	MaxResponseBytes int
	// Kubeconfig is the default kubeconfig path (already expanded).
	Kubeconfig string
	// AdditionalSensitiveResources extends the built-in sensitive set.
	AdditionalSensitiveResources []string
	// NamespaceMarker configures the optional namespace marker overlay.
	NamespaceMarker NamespaceMarkerConfig
}

// NamespaceMarkerConfig configures the optional namespace marker overlay.
type NamespaceMarkerConfig struct {
	// Enabled reports whether the marker overlay is active.
	Enabled bool
	// Label is the namespace label key that marks a namespace as protected.
	Label string
}

// ProviderConfig describes one group of clusters and the rules that govern
// access to them.
type ProviderConfig struct {
	// Name uniquely identifies the provider.
	Name string `yaml:"name"`
	// Kubeconfig is the provider's kubeconfig path (already expanded); empty
	// falls back to the server default.
	Kubeconfig string `yaml:"kubeconfig"`
	// Contexts selects the kubeconfig contexts belonging to this provider.
	Contexts []string `yaml:"contexts"`
	// PolicyRead enables the policy-introspection tools for this provider.
	PolicyRead bool `yaml:"policy_read"`
	// Rules are the ordered authorization rules.
	Rules []RuleConfig `yaml:"rules"`

	// QPS, Burst, RequestTimeout, DiscoveryTimeout and DiscoveryCacheTTL
	// override the server defaults when non-nil.
	QPS               *float64  `yaml:"qps"`
	Burst             *int      `yaml:"burst"`
	RequestTimeout    *Duration `yaml:"request_timeout"`
	DiscoveryTimeout  *Duration `yaml:"discovery_timeout"`
	DiscoveryCacheTTL *Duration `yaml:"discovery_cache_ttl"`
}

// RuleConfig is one ordered authorization rule: a namespace scope, an effect and
// the capabilities it grants or denies.
type RuleConfig struct {
	// Namespaces is the non-empty scope of the rule. The literal "" selects
	// cluster-scoped resources; all other entries are doublestar globs.
	Namespaces []string `yaml:"namespaces"`
	// Effect is "allow" or "deny"; it is required.
	Effect policy.Effect `yaml:"effect"`
	// Capabilities lists the entries the rule applies to. An allow rule needs
	// at least one; a deny rule with none denies every capability in scope.
	Capabilities []CapabilityGrant `yaml:"capabilities"`
}

// rawConfig mirrors Config for parsing, keeping presence information so that an
// explicit zero can be told apart from an omitted field.
type rawConfig struct {
	Version   *int             `yaml:"version"`
	Server    rawServer        `yaml:"server"`
	Providers []ProviderConfig `yaml:"providers"`
}

type rawServer struct {
	Name                         string             `yaml:"name"`
	LogLevel                     string             `yaml:"log_level"`
	RequestTimeout               *Duration          `yaml:"request_timeout"`
	DiscoveryTimeout             *Duration          `yaml:"discovery_timeout"`
	DiscoveryCacheTTL            *Duration          `yaml:"discovery_cache_ttl"`
	QPS                          *float64           `yaml:"qps"`
	Burst                        *int               `yaml:"burst"`
	MaxListItems                 *int               `yaml:"max_list_items"`
	MaxObjectBytes               *int               `yaml:"max_object_bytes"`
	MaxResponseBytes             *int               `yaml:"max_response_bytes"`
	Kubeconfig                   string             `yaml:"kubeconfig"`
	AdditionalSensitiveResources []string           `yaml:"additional_sensitive_resources"`
	NamespaceMarker              rawNamespaceMarker `yaml:"namespace_marker"`
}

type rawNamespaceMarker struct {
	Enabled bool   `yaml:"enabled"`
	Label   string `yaml:"label"`
}

// Load reads, parses, defaults and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

// Parse parses, applies defaults to and validates a YAML configuration. Parsing
// is strict: an unknown key is an error.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var raw rawConfig
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("configuration is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := rejectExtraDocuments(dec); err != nil {
		return nil, err
	}
	cfg := applyDefaults(&raw)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// rejectExtraDocuments fails when the stream contains more than one document.
func rejectExtraDocuments(dec *yaml.Decoder) error {
	var extra yaml.Node
	err := dec.Decode(&extra)
	switch {
	case err == nil:
		return errors.New("multiple YAML documents are not supported")
	case errors.Is(err, io.EOF):
		return nil
	default:
		return fmt.Errorf("parse config: %w", err)
	}
}

// applyDefaults fills every omitted field with its documented default.
func applyDefaults(raw *rawConfig) *Config {
	cfg := &Config{Version: defaultVersion}
	if raw.Version != nil {
		cfg.Version = *raw.Version
	}
	cfg.Server = applyServerDefaults(raw.Server)
	cfg.Providers = raw.Providers
	for i := range cfg.Providers {
		cfg.Providers[i].Kubeconfig = expandPath(cfg.Providers[i].Kubeconfig)
	}
	return cfg
}

func applyServerDefaults(raw rawServer) ServerConfig {
	server := ServerConfig{
		Name:                         raw.Name,
		LogLevel:                     LogLevel(raw.LogLevel),
		RequestTimeout:               Duration(defaultRequestTimeout),
		DiscoveryTimeout:             Duration(defaultDiscoveryTimeout),
		DiscoveryCacheTTL:            Duration(defaultDiscoveryCacheTTL),
		QPS:                          defaultQPS,
		Burst:                        defaultBurst,
		MaxListItems:                 defaultMaxListItems,
		MaxObjectBytes:               defaultMaxObjectBytes,
		MaxResponseBytes:             defaultMaxResponseBytes,
		Kubeconfig:                   expandPath(raw.Kubeconfig),
		AdditionalSensitiveResources: raw.AdditionalSensitiveResources,
		NamespaceMarker: NamespaceMarkerConfig{
			Enabled: raw.NamespaceMarker.Enabled,
			Label:   raw.NamespaceMarker.Label,
		},
	}
	if server.Name == "" {
		server.Name = defaultName
	}
	if server.LogLevel == "" {
		server.LogLevel = defaultLogLevel
	}
	if raw.RequestTimeout != nil {
		server.RequestTimeout = *raw.RequestTimeout
	}
	if raw.DiscoveryTimeout != nil {
		server.DiscoveryTimeout = *raw.DiscoveryTimeout
	}
	if raw.DiscoveryCacheTTL != nil {
		server.DiscoveryCacheTTL = *raw.DiscoveryCacheTTL
	}
	if raw.QPS != nil {
		server.QPS = *raw.QPS
	}
	if raw.Burst != nil {
		server.Burst = *raw.Burst
	}
	if raw.MaxListItems != nil {
		server.MaxListItems = *raw.MaxListItems
	}
	if raw.MaxObjectBytes != nil {
		server.MaxObjectBytes = *raw.MaxObjectBytes
	}
	if raw.MaxResponseBytes != nil {
		server.MaxResponseBytes = *raw.MaxResponseBytes
	}
	if server.NamespaceMarker.Label == "" {
		server.NamespaceMarker.Label = defaultNamespaceMarkerLabel
	}
	return server
}

// validate fails closed on any invalid field, naming the offending path.
func (c *Config) validate() error {
	if c.Version != defaultVersion {
		return fmt.Errorf("version: must be %d, got %d", defaultVersion, c.Version)
	}
	if err := c.Server.validate(); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	if len(c.Providers) == 0 {
		return errors.New("providers: at least one provider is required")
	}
	seen := make(map[string]struct{}, len(c.Providers))
	for i := range c.Providers {
		provider := &c.Providers[i]
		if provider.Name == "" {
			return fmt.Errorf("providers[%d].name: must not be empty", i)
		}
		if _, duplicate := seen[provider.Name]; duplicate {
			return fmt.Errorf("providers[%d].name: duplicate provider name %q", i, provider.Name)
		}
		seen[provider.Name] = struct{}{}
		if err := provider.validate(); err != nil {
			return fmt.Errorf("providers[%d]: %w", i, err)
		}
	}
	return nil
}

func (s *ServerConfig) validate() error {
	if s.Name == "" {
		return errors.New("name: must not be empty")
	}
	switch s.LogLevel {
	case LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
	default:
		return fmt.Errorf("log_level: must be one of debug, info, warn, error, got %q", s.LogLevel)
	}
	if s.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout: must be > 0, got %s", s.RequestTimeout)
	}
	if s.DiscoveryTimeout <= 0 {
		return fmt.Errorf("discovery_timeout: must be > 0, got %s", s.DiscoveryTimeout)
	}
	if s.DiscoveryCacheTTL < 0 {
		return fmt.Errorf("discovery_cache_ttl: must be >= 0, got %s", s.DiscoveryCacheTTL)
	}
	if s.QPS <= 0 {
		return fmt.Errorf("qps: must be > 0, got %v", s.QPS)
	}
	if s.Burst <= 0 {
		return fmt.Errorf("burst: must be > 0, got %d", s.Burst)
	}
	if s.MaxListItems <= 0 || s.MaxListItems > maxListItemsLimit {
		return fmt.Errorf("max_list_items: must be > 0 and <= %d, got %d", maxListItemsLimit, s.MaxListItems)
	}
	if s.MaxObjectBytes <= 0 {
		return fmt.Errorf("max_object_bytes: must be > 0, got %d", s.MaxObjectBytes)
	}
	if s.MaxResponseBytes <= 0 {
		return fmt.Errorf("max_response_bytes: must be > 0, got %d", s.MaxResponseBytes)
	}
	for i, resource := range s.AdditionalSensitiveResources {
		if err := validateResourceSyntax(resource, false); err != nil {
			return fmt.Errorf("additional_sensitive_resources[%d]: %w", i, err)
		}
	}
	if !validLabelKey(s.NamespaceMarker.Label) {
		return fmt.Errorf("namespace_marker.label: %q is not a valid Kubernetes label key", s.NamespaceMarker.Label)
	}
	return nil
}

func (p *ProviderConfig) validate() error {
	if len(p.Contexts) == 0 {
		return errors.New("contexts: at least one context is required")
	}
	for i, context := range p.Contexts {
		if !doublestar.ValidatePattern(context) {
			return fmt.Errorf("contexts[%d]: invalid glob %q", i, context)
		}
	}
	if p.QPS != nil && *p.QPS <= 0 {
		return fmt.Errorf("qps: must be > 0, got %v", *p.QPS)
	}
	if p.Burst != nil && *p.Burst <= 0 {
		return fmt.Errorf("burst: must be > 0, got %d", *p.Burst)
	}
	if p.RequestTimeout != nil && *p.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout: must be > 0, got %s", *p.RequestTimeout)
	}
	if p.DiscoveryTimeout != nil && *p.DiscoveryTimeout <= 0 {
		return fmt.Errorf("discovery_timeout: must be > 0, got %s", *p.DiscoveryTimeout)
	}
	if p.DiscoveryCacheTTL != nil && *p.DiscoveryCacheTTL < 0 {
		return fmt.Errorf("discovery_cache_ttl: must be >= 0, got %s", *p.DiscoveryCacheTTL)
	}
	for i := range p.Rules {
		if err := p.Rules[i].validate(); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

func (r *RuleConfig) validate() error {
	if r.Effect == "" {
		return errors.New("effect: is required")
	}
	if r.Effect != policy.EffectAllow && r.Effect != policy.EffectDeny {
		return fmt.Errorf("effect: must be allow or deny, got %q", r.Effect)
	}
	if len(r.Namespaces) == 0 {
		return errors.New("namespaces: must not be empty")
	}
	for i, namespace := range r.Namespaces {
		if namespace == "" {
			continue
		}
		if !doublestar.ValidatePattern(namespace) {
			return fmt.Errorf("namespaces[%d]: invalid glob %q", i, namespace)
		}
	}
	if r.Effect == policy.EffectAllow && len(r.Capabilities) == 0 {
		return errors.New("capabilities: an allow rule must list at least one capability")
	}
	for i := range r.Capabilities {
		if err := r.Capabilities[i].validate(r.Effect); err != nil {
			return fmt.Errorf("capabilities[%d]: %w", i, err)
		}
	}
	return nil
}

var (
	resourceTokenRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	envRefRE        = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	labelNameRE     = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
	dnsLabelRE      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// validateResourceSyntax checks the resource grammar of ADR 0012 (syntax only):
// "[group/]resource[/subresource]", 1 to 3 non-empty lowercase tokens, or the
// standalone "*" when allowWildcard is true.
func validateResourceSyntax(resource string, allowWildcard bool) error {
	if resource == "" {
		return errors.New("resource must not be empty")
	}
	if resource == "*" {
		if !allowWildcard {
			return errors.New(`"*" is not allowed here`)
		}
		return nil
	}
	parts := strings.Split(resource, "/")
	if len(parts) > 3 {
		return fmt.Errorf("resource %q must have at most 3 slash-separated parts", resource)
	}
	for _, part := range parts {
		switch {
		case part == "":
			return fmt.Errorf("resource %q has an empty part", resource)
		case part == "*":
			return errors.New(`resource wildcard "*" must stand alone as the whole resource`)
		case part != strings.ToLower(part):
			return fmt.Errorf("resource %q must be lowercase", resource)
		case !resourceTokenRE.MatchString(part):
			return fmt.Errorf("resource %q has an invalid token %q", resource, part)
		}
	}
	return nil
}

// validateLabelFilter checks that every entry is non-empty and that no entry is
// both required and excluded.
func validateLabelFilter(filter policy.LabelFilter) error {
	for _, entry := range filter.Require {
		if entry == "" {
			return errors.New("empty labels.require entry")
		}
	}
	for _, entry := range filter.Exclude {
		if entry == "" {
			return errors.New("empty labels.exclude entry")
		}
	}
	for _, entry := range filter.Require {
		for _, excluded := range filter.Exclude {
			if entry == excluded {
				return fmt.Errorf("label %q is both required and excluded", entry)
			}
		}
	}
	return nil
}

// validateNameFilter checks that every include and exclude pattern is a valid
// doublestar glob.
func validateNameFilter(filter policy.NameFilter) error {
	for _, pattern := range filter.Include {
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("invalid names.include pattern %q", pattern)
		}
	}
	for _, pattern := range filter.Exclude {
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("invalid names.exclude pattern %q", pattern)
		}
	}
	return nil
}

// validLabelKey reports whether s is a plausible Kubernetes label key: an
// optional DNS-subdomain prefix, a slash and a name.
func validLabelKey(s string) bool {
	prefix, name, found := strings.Cut(s, "/")
	if !found {
		name = prefix
	} else if !validDNSSubdomain(prefix) {
		return false
	}
	return name != "" && len(name) <= 63 && labelNameRE.MatchString(name)
}

func validDNSSubdomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || len(part) > 63 || !dnsLabelRE.MatchString(part) {
			return false
		}
	}
	return true
}

// expandPath expands a leading "~" to the user's home directory and every
// "${NAME}" environment reference (whole-variable syntax only). An empty path is
// returned unchanged.
func expandPath(path string) string {
	if path == "" {
		return ""
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = home + path[1:]
		}
	}
	return envRefRE.ReplaceAllStringFunc(path, func(match string) string {
		return os.Getenv(match[2 : len(match)-1])
	})
}
