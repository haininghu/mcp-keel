package kube

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestHTTPStatusTyped(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "x", errors.New("denied"))
	err := safeError(forbidden)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("safeError(forbidden) = %v, want ErrForbidden", err)
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("safeError(forbidden) type = %T, want *StatusError", err)
	}
	if got := HTTPStatus(err); got != 403 {
		t.Fatalf("HTTPStatus(forbidden) = %d, want 403", got)
	}
	if got := err.Error(); got != "kube: forbidden (HTTP 403)" {
		t.Fatalf("Error() = %q, want kube: forbidden (HTTP 403)", got)
	}

	unauthorized := apierrors.NewUnauthorized("nope")
	if got := HTTPStatus(safeError(unauthorized)); got != 401 {
		t.Fatalf("HTTPStatus(unauthorized) = %d, want 401", got)
	}

	// A sentinel without a status carries none.
	if got := HTTPStatus(withStatus(ErrRequestFailed, errors.New("boom"))); got != 0 {
		t.Fatalf("HTTPStatus(statusless) = %d, want 0", got)
	}
	if got := HTTPStatus(ErrNotFound); got != 0 {
		t.Fatalf("HTTPStatus(ErrNotFound) = %d, want 0", got)
	}
}
