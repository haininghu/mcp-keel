package kube

import (
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Sentinel errors of the kube layer. They deliberately carry no server response
// body so callers can map them to safe client-facing messages (ADR 0008,
// ADR 0014).
var (
	// ErrNotFound reports that the requested object does not exist, or that the
	// API server concealed its existence.
	ErrNotFound = errors.New("kube: not found")
	// ErrForbidden reports that the configured identity lacks RBAC permission.
	ErrForbidden = errors.New("kube: forbidden")
	// ErrUnauthorized reports that the API server rejected the credentials.
	ErrUnauthorized = errors.New("kube: unauthorized")
	// ErrRequestFailed reports any other failed API request.
	ErrRequestFailed = errors.New("kube: request failed")

	// ErrUnknownResource reports that a resource identifier could not be
	// resolved through discovery, or does not support the requested verb.
	ErrUnknownResource = errors.New("unknown resource")
	// ErrAmbiguousResource reports that an unqualified resource identifier
	// matched more than one API group.
	ErrAmbiguousResource = errors.New("ambiguous resource")
	// ErrInvalidResource reports a malformed resource identifier.
	ErrInvalidResource = errors.New("invalid resource")
	// ErrUnsupportedVerb reports that a resolved resource does not support the
	// requested verb.
	ErrUnsupportedVerb = errors.New("unsupported verb")
	// ErrPartialDiscovery reports that discovery was incomplete, so an
	// unqualified resource name was denied fail-closed (ADR 0012, ADR 0014).
	ErrPartialDiscovery = errors.New("discovery partial")

	// ErrCredentialsUnavailable reports that the kubeconfig's credential plugin
	// could not provide credentials, for example because its login expired. It
	// carries only a safe classification, never plugin output (ADR 0007).
	ErrCredentialsUnavailable = errors.New("kube: credentials unavailable")

	// ErrPrometheusBusy reports that the per-provider Prometheus query
	// concurrency limit was reached; the excess query is rejected immediately,
	// never queued (ADR 0017).
	ErrPrometheusBusy = errors.New("kube: prometheus concurrency limit reached")
	// ErrPrometheusTimeout reports that a Prometheus query exceeded its
	// server-set deadline (ADR 0017).
	ErrPrometheusTimeout = errors.New("kube: prometheus query timed out")
	// ErrPrometheusResponseTooLarge reports that a Prometheus response exceeded
	// the body budget (ADR 0017).
	ErrPrometheusResponseTooLarge = errors.New("kube: prometheus response too large")
	// ErrPrometheusUpstream reports an upstream failure that must not expose its
	// body: a 3xx, 5xx, non-JSON or API-server error (ADR 0017).
	ErrPrometheusUpstream = errors.New("kube: prometheus upstream error")
	// ErrPrometheusInvalid reports that Prometheus rejected the query; the
	// sanitized errorType/error is carried by PrometheusError.
	ErrPrometheusInvalid = errors.New("kube: prometheus query rejected")

	// ErrUnknownProvider reports an unknown provider name.
	ErrUnknownProvider = errors.New("kube: unknown provider")
	// ErrUnknownContext reports a context outside a provider's contexts.
	ErrUnknownContext = errors.New("kube: unknown context")
)

// CredentialError is the classified form of a credential-plugin failure. It
// names the configured plugin command (its base name) so the agent can act on
// it, but deliberately drops the wrapped error: the plugin's output may contain
// secret material (ADR 0007).
type CredentialError struct {
	// Plugin is the base name of the configured credential plugin command, or
	// empty when it is unknown.
	Plugin string
}

// Error renders the safe classification without plugin output.
func (e *CredentialError) Error() string {
	if e.Plugin == "" {
		return ErrCredentialsUnavailable.Error()
	}
	return fmt.Sprintf("kube: credential plugin %q failed", e.Plugin)
}

// Unwrap returns the sentinel so errors.Is matches ErrCredentialsUnavailable.
func (e *CredentialError) Unwrap() error { return ErrCredentialsUnavailable }

// PrometheusError is the sanitized form of a Prometheus error response. It
// carries only the errorType and the message, both stripped of control
// characters and length-capped (ADR 0017); it never carries the raw upstream
// body.
type PrometheusError struct {
	// ErrorType is the Prometheus errorType (for example "bad_data").
	ErrorType string
	// Message is the sanitized Prometheus error message (already capped).
	Message string
}

// Error renders the safe classification without the raw upstream body.
func (e *PrometheusError) Error() string {
	if e.ErrorType == "" {
		e.ErrorType = "unknown"
	}
	if e.Message == "" {
		return fmt.Sprintf("kube: prometheus query failed (%s)", e.ErrorType)
	}
	return fmt.Sprintf("kube: prometheus query failed (%s): %s", e.ErrorType, e.Message)
}

// Unwrap returns the sentinel so errors.Is matches ErrPrometheusInvalid.
func (e *PrometheusError) Unwrap() error { return ErrPrometheusInvalid }

// isCredentialPluginError reports whether err came from a kubeconfig exec
// credential plugin. client-go reports these as plain formatted errors (it
// discards the *exec.ExitError type), so the stable message markers are matched.
// It is only consulted when the context is known to use an exec plugin.
func isCredentialPluginError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "exec: executable") || strings.Contains(msg, "exec plugin")
}

// safeError maps a client-go API error to a sentinel-based error that never
// contains a server response body. Only the HTTP status code is preserved, and
// only for the statuses the server surfaces to the caller (ADR 0008).
func safeError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case apierrors.IsNotFound(err):
		return ErrNotFound
	case apierrors.IsForbidden(err):
		return withStatus(ErrForbidden, err)
	case apierrors.IsUnauthorized(err):
		return withStatus(ErrUnauthorized, err)
	default:
		return withStatus(ErrRequestFailed, err)
	}
}

// StatusError is a sentinel-based kube error that additionally carries the HTTP
// status code observed from the API server. It never contains a response body;
// callers read the code through HTTPStatus.
type StatusError struct {
	// Sentinel is the kube sentinel the error maps to, so errors.Is keeps
	// working against ErrForbidden, ErrUnauthorized and ErrRequestFailed.
	Sentinel error
	// Code is the HTTP status code, or 0 when none was available.
	Code int
}

// Error renders the safe message, appending the HTTP status when known.
func (e *StatusError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("%s (HTTP %d)", e.Sentinel, e.Code)
	}
	return e.Sentinel.Error()
}

// Unwrap returns the sentinel so errors.Is matches the kube sentinels.
func (e *StatusError) Unwrap() error { return e.Sentinel }

// HTTPStatus returns the HTTP status code the kube layer attached to err, or 0
// when err carries no status. It uses a typed assertion and never parses the
// error string.
func HTTPStatus(err error) int {
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.Code
	}
	return 0
}

// withStatus attaches the error's HTTP status code to sentinel when it carries
// one, so the server can surface "forbidden (HTTP 403)" without a response body.
func withStatus(sentinel, err error) error {
	if code := apiStatusCode(err); code != 0 {
		return &StatusError{Sentinel: sentinel, Code: code}
	}
	return sentinel
}

// apiStatusCode returns the HTTP status code of a client-go API status error,
// or 0 when the error carries no status.
func apiStatusCode(err error) int {
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		return int(status.Status().Code)
	}
	return 0
}
