package operator

import (
	"context"
	"io"
	"net/http"
	"time"

	"k8s.io/client-go/rest"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
)

// RestConfig returns cfg with the tuned client settings applied. Each
// request takes api_timeout from l when it starts.
func RestConfig(cfg *rest.Config, l *tuning.Live) *rest.Config {
	s := l.Load()
	cfg = rest.CopyConfig(cfg)
	cfg.QPS = float32(s.APIQPS)
	cfg.Burst = s.APIBurst
	cfg.Timeout = 0
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { return deadlineTransport{rt, l} })
	return cfg
}

type deadlineTransport struct {
	next     http.RoundTripper
	settings *tuning.Live
}

func (d deadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	timer := time.AfterFunc(d.settings.Load().APITimeout, cancel)
	resp, err := d.next.RoundTrip(req.WithContext(ctx))
	if err != nil {
		timer.Stop()
		cancel()
		return nil, err
	}
	if isWatch(req) {
		// Headers arrived; the stream is bounded by the caller's context
		// and the server's timeoutSeconds.
		timer.Stop()
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, stop: func() { timer.Stop(); cancel() }}
	return resp, nil
}

type cancelOnClose struct {
	io.ReadCloser
	stop func()
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.stop()
	return err
}

// isWatch reports whether req opens a watch stream, including a WatchList
// (sendInitialEvents) request.
func isWatch(req *http.Request) bool {
	switch req.URL.Query().Get("watch") {
	case "true", "1":
		return true
	}
	return false
}
