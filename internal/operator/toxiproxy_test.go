//go:build resilience

package operator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

// toxiproxyServer is one toxiproxy-server process for the package, driven
// through its HTTP API.
var toxiproxyServer struct {
	once sync.Once
	api  string
	err  error
}

func toxiproxyAPI(t *testing.T) string {
	t.Helper()
	toxiproxyServer.once.Do(func() {
		bin := os.Getenv("TOXIPROXY_SERVER")
		if bin == "" {
			bin = filepath.Join("..", "..", "bin", "toxiproxy-server")
		}
		port, err := freePort()
		if err != nil {
			toxiproxyServer.err = err
			return
		}
		cmd := exec.Command(bin, "-host", "127.0.0.1", "-port", fmt.Sprint(port))
		// TestMain has already cleared GODEBUG; keep the proxy's own
		// logging out of the test output unless asked for.
		if os.Getenv("TEST_VERBOSE") != "" {
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		}
		if err := cmd.Start(); err != nil {
			toxiproxyServer.err = fmt.Errorf("start %s (run make toxiproxy): %w", bin, err)
			return
		}
		suiteCleanups = append(suiteCleanups, func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		api := fmt.Sprintf("http://127.0.0.1:%d", port)
		deadline := time.Now().Add(10 * time.Second)
		for {
			resp, err := http.Get(api + "/version")
			if err == nil {
				_ = resp.Body.Close()
				break
			}
			if time.Now().After(deadline) {
				toxiproxyServer.err = fmt.Errorf("toxiproxy-server did not answer: %w", err)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		toxiproxyServer.api = api
	})
	if toxiproxyServer.err != nil {
		t.Fatal(toxiproxyServer.err)
	}
	return toxiproxyServer.api
}

// apiProxy is one Toxiproxy proxy in front of the envtest API server.
type apiProxy struct {
	t      *testing.T
	api    string
	name   string
	listen string
}

// newAPIProxy creates a proxy to the envtest API server, removed when the
// test ends.
func newAPIProxy(t *testing.T, name string) *apiProxy {
	t.Helper()
	api := toxiproxyAPI(t)
	upstream, err := url.Parse(cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Listen string `json:"listen"`
	}
	toxiproxyCall(t, api, http.MethodPost, "/proxies", map[string]any{
		"name": name, "listen": "127.0.0.1:0", "upstream": upstream.Host, "enabled": true,
	}, &out)
	p := &apiProxy{t: t, api: api, name: name, listen: out.Listen}
	t.Cleanup(func() { toxiproxyCall(t, api, http.MethodDelete, "/proxies/"+name, nil, nil) })
	return p
}

// restConfig is the envtest admin config, reaching the API server through
// the proxy.
func (p *apiProxy) restConfig() *rest.Config {
	c := rest.CopyConfig(cfg)
	c.Host = "https://" + p.listen
	return c
}

// setEnabled false closes every open connection and refuses new ones;
// true listens again on the same address.
func (p *apiProxy) setEnabled(enabled bool) {
	p.t.Helper()
	toxiproxyCall(p.t, p.api, http.MethodPost, "/proxies/"+p.name, map[string]any{"enabled": enabled}, nil)
}

// addToxic adds a toxic to the stream ("upstream" is towards the API
// server, "downstream" towards the operator).
func (p *apiProxy) addToxic(name, typ, stream string, attrs map[string]any) {
	p.t.Helper()
	toxiproxyCall(p.t, p.api, http.MethodPost, "/proxies/"+p.name+"/toxics", map[string]any{
		"name": name, "type": typ, "stream": stream, "toxicity": 1.0, "attributes": attrs,
	}, nil)
}

func (p *apiProxy) removeToxic(name string) {
	p.t.Helper()
	toxiproxyCall(p.t, p.api, http.MethodDelete, "/proxies/"+p.name+"/toxics/"+name, nil, nil)
}

func toxiproxyCall(t *testing.T, api, method, path string, body, out any) {
	t.Helper()
	var r *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, api+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("toxiproxy %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		var msg bytes.Buffer
		_, _ = msg.ReadFrom(resp.Body)
		t.Fatalf("toxiproxy %s %s: %s %s", method, path, resp.Status, msg.String())
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("toxiproxy %s %s: %v", method, path, err)
		}
	}
}
