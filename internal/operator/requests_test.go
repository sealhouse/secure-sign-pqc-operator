package operator

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/client-go/rest"
)

// requests records the operator's API calls below its deadline transport:
// how many it makes, how long each failed one ran, and how many watches it
// opens.
type requests struct {
	count   atomic.Int64
	watches atomic.Int64
	mu      sync.Mutex
	// failed holds the duration of every non-watch request that failed.
	failed []time.Duration
}

func (r *requests) wrap(c *rest.Config) *rest.Config {
	c = rest.CopyConfig(c)
	c.Wrap(func(rt http.RoundTripper) http.RoundTripper { return requestsTransport{rt, r} })
	return c
}

func (r *requests) failures() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.failed...)
}

type requestsTransport struct {
	next http.RoundTripper
	r    *requests
}

func (t requestsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if isWatch(req) {
		t.r.watches.Add(1)
		return t.next.RoundTrip(req)
	}
	t.r.count.Add(1)
	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		t.r.mu.Lock()
		t.r.failed = append(t.r.failed, time.Since(start))
		t.r.mu.Unlock()
	}
	return resp, err
}
