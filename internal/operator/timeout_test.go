package operator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
)

type countWatches struct {
	next    http.RoundTripper
	watches *atomic.Int32
}

func (c countWatches) RoundTrip(req *http.Request) (*http.Response, error) {
	if isWatch(req) {
		c.watches.Add(1)
	}
	return c.next.RoundTrip(req)
}

// api_timeout bounds requests, not watch streams: informers keep their
// watches open well past it instead of reconnecting every api_timeout.
func TestAPITimeoutLeavesWatchesOpen(t *testing.T) {
	var watches atomic.Int32
	c := rest.CopyConfig(cfg)
	c.Wrap(func(rt http.RoundTripper) http.RoundTripper { return countWatches{rt, &watches} })
	startOperatorWith(t, c, createNamespace(t, "op"), func(o *Options) { o.Effective.APITimeout = time.Second })
	eventually(t, 10*time.Second, "informers watching", func() error {
		if watches.Load() == 0 {
			return fmt.Errorf("no watches")
		}
		return nil
	})
	time.Sleep(2 * time.Second)
	settled := watches.Load()
	time.Sleep(4 * time.Second)
	if n := watches.Load(); n != settled {
		t.Fatalf("%d watch requests in 4 s with a 1 s api_timeout; watches are being cut", n-settled)
	}
}

func TestDeadlineTransport(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hang":
			<-release
		case "/slow-body":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-release
		case "/stream":
			w.WriteHeader(http.StatusOK)
			for i := range 6 {
				_, _ = fmt.Fprintln(w, i)
				w.(http.Flusher).Flush()
				time.Sleep(100 * time.Millisecond)
			}
		}
	}))
	// Unblock the hung handlers before Close waits for them.
	defer srv.Close()
	defer close(release)
	settings := tuning.Defaults()
	settings.APITimeout = 200 * time.Millisecond
	live := tuning.NewLive(settings)
	c := RestConfig(&rest.Config{Host: srv.URL}, live)
	hc, err := rest.HTTPClientFor(c)
	if err != nil {
		t.Fatal(err)
	}
	if hc.Timeout != 0 {
		t.Fatalf("http.Client.Timeout %v would cut watches", hc.Timeout)
	}
	get := func(path string) (string, error) {
		resp, err := hc.Get(srv.URL + path)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}

	for _, path := range []string{"/hang", "/slow-body", "/hang?watch=true"} {
		start := time.Now()
		_, err := get(path)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: err %v, want the deadline to cancel it", path, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("%s: took %v with a 200 ms deadline", path, d)
		}
	}
	body, err := get("/stream?watch=true")
	if err != nil {
		t.Fatalf("watch stream cut: %v", err)
	}
	if body != "0\n1\n2\n3\n4\n5\n" {
		t.Fatalf("watch body %q", body)
	}
	if _, err := get("/stream"); err == nil {
		t.Fatal("a 600 ms non-watch response passed a 200 ms deadline")
	}
	// A new api_timeout applies to the next request on the same client.
	settings.APITimeout = 5 * time.Second
	live.Store(settings)
	if _, err := get("/stream"); err != nil {
		t.Fatalf("a 600 ms response with a 5 s api_timeout: %v", err)
	}
}
