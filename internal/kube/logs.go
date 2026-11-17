package kube

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

// maxLogBytes is the hard cap on a single log read when the caller passes no
// positive LimitBytes. It bounds memory: the endpoint streams, so without a cap
// an arbitrarily large log would be read in full.
const maxLogBytes int64 = 16 << 20

// LogOptions selects and bounds a pod log read.
type LogOptions struct {
	// Container names the container to read. An empty value selects the only
	// container, or fails when the pod has more than one.
	Container string
	// Previous reads the log of the container's previous instance.
	Previous bool
	// Timestamps prefixes each line with an RFC 3339 timestamp.
	Timestamps bool
	// TailLines limits the read to the last n lines.
	TailLines *int64
	// SinceSeconds limits the read to lines newer than n seconds.
	SinceSeconds *int64
	// LimitBytes asks the API server for at most n bytes of log output. A
	// positive value is also the client-side read cap.
	LimitBytes *int64
}

// Logs reads a bounded window of a pod's log. It never follows the stream and
// returns the raw bytes verbatim. API errors are mapped to sentinels and never
// expose a response body.
func (c *Cluster) Logs(ctx context.Context, namespace, pod string, opts LogOptions) ([]byte, error) {
	if namespace == "" {
		return nil, fmt.Errorf("kube: namespace must not be empty")
	}
	if pod == "" {
		return nil, fmt.Errorf("kube: pod name must not be empty")
	}
	podOpts := corev1.PodLogOptions{
		Container:    opts.Container,
		Follow:       false,
		Previous:     opts.Previous,
		Timestamps:   opts.Timestamps,
		TailLines:    opts.TailLines,
		SinceSeconds: opts.SinceSeconds,
		LimitBytes:   opts.LimitBytes,
	}
	stream, err := c.logs.Get().
		Namespace(namespace).
		Resource("pods").
		Name(pod).
		SubResource("log").
		VersionedParams(&podOpts, scheme.ParameterCodec).
		Stream(ctx)
	if err != nil {
		return nil, c.safeAPIError(err)
	}
	limit := maxLogBytes
	if opts.LimitBytes != nil && *opts.LimitBytes > 0 {
		limit = *opts.LimitBytes
	}
	data, readErr := io.ReadAll(io.LimitReader(stream, limit))
	_ = stream.Close()
	if readErr != nil {
		return nil, c.safeAPIError(readErr)
	}
	return data, nil
}
