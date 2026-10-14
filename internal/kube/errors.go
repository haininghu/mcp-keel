package kube

import (
	"errors"
	"fmt"

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

	// ErrUnknownProvider reports an unknown provider name.
	ErrUnknownProvider = errors.New("kube: unknown provider")
	// ErrUnknownContext reports a context outside a provider's contexts.
	ErrUnknownContext = errors.New("kube: unknown context")
)

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
func withStatus(sentinel error, err error) error {
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
