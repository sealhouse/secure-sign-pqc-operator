package operator

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/client-go/rest"
)

// requests records the operator's API calls below its deadline transport:
// how many it makes, how long each failed one ran, how many watches it
// opens and on which resources, and each call by method, object and
// response. leases counts the leader election calls within count.
type requests struct {
	count   atomic.Int64
	leases  atomic.Int64
	watches atomic.Int64
	mu      sync.Mutex
	// failed holds the duration of every non-watch request that failed.
	failed  []time.Duration
	calls   map[string]int
	watched map[string]bool
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

// watching reports which of resources no watch has been opened on yet.
// An informer opens its watch once its initial list is in.
func (r *requests) watching(resources ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var missing []string
	for _, res := range resources {
		if !r.watched[res] {
			missing = append(missing, res)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("no watch on %v yet", missing)
	}
	return nil
}

// byCall is a copy of the call counts so far.
func (r *requests) byCall() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.calls)
}

// callsSince lists the calls made since before, most frequent first.
func (r *requests) callsSince(before map[string]int) string {
	type row struct {
		call string
		n    int
	}
	var rows []row
	for k, v := range r.byCall() {
		if n := v - before[k]; n > 0 {
			rows = append(rows, row{k, n})
		}
	}
	slices.SortFunc(rows, func(a, b row) int {
		return cmp.Or(cmp.Compare(b.n, a.n), cmp.Compare(a.call, b.call))
	})
	var b strings.Builder
	for _, x := range rows {
		fmt.Fprintf(&b, "\n  %4d %s", x.n, x.call)
	}
	return b.String()
}

type requestsTransport struct {
	next http.RoundTripper
	r    *requests
}

func (t requestsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if isWatch(req) {
		t.r.watches.Add(1)
		t.r.mu.Lock()
		if t.r.watched == nil {
			t.r.watched = map[string]bool{}
		}
		t.r.watched[callObject(req.URL.Path)] = true
		t.r.mu.Unlock()
		return t.next.RoundTrip(req)
	}
	t.r.count.Add(1)
	obj := callObject(req.URL.Path)
	if obj == "leases" || strings.HasPrefix(obj, "leases/") {
		t.r.leases.Add(1)
	}
	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	code := "error"
	if err == nil {
		code = fmt.Sprint(resp.StatusCode)
	}
	t.r.mu.Lock()
	if err != nil {
		t.r.failed = append(t.r.failed, time.Since(start))
	}
	if t.r.calls == nil {
		t.r.calls = map[string]int{}
	}
	t.r.calls[fmt.Sprintf("%s %s %s", req.Method, obj, code)]++
	t.r.mu.Unlock()
	return resp, err
}

// callObject is a request path without its API group, version and
// namespace: "secrets/demo-tsa-root-1", "securesignpqcs/demo/status".
func callObject(path string) string {
	p := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(p) >= 2 && p[0] == "api":
		p = p[2:]
	case len(p) >= 3 && p[0] == "apis":
		p = p[3:]
	default:
		return path
	}
	if len(p) >= 3 && p[0] == "namespaces" {
		p = p[2:]
	}
	return strings.Join(p, "/")
}
