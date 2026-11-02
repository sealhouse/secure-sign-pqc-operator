//go:build resilience

package operator

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
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

// reconciles is the controller's reconcile count so far, from the
// controller-runtime registry every manager in the process shares.
func reconciles(t *testing.T) float64 {
	t.Helper()
	return controllerMetric(t, "controller_runtime_reconcile_total")
}

// activeWorkers is how many of the controller's reconciles are running.
func activeWorkers(t *testing.T) float64 {
	t.Helper()
	return controllerMetric(t, "controller_runtime_active_workers")
}

func controllerMetric(t *testing.T, name string) float64 {
	t.Helper()
	return metricValue(t, metrics.Registry, name, map[string]string{"controller": "securesignpqc"})
}

// The API server accepts connections but never answers.
func TestResilienceAPIServerSilent(t *testing.T) {
	settings := resilienceSettings()
	settings.APITimeout = 2 * time.Second
	p := newAPIProxy(t, "silent")
	var reqs requests
	opns := createNamespace(t, "op")
	sup := supervise(t, supervisorOptions{restCfg: reqs.wrap(p.restConfig()), namespace: opns, env: settings})
	ns := createNamespace(t, "silent")
	installReady(t, ns, time.Minute)
	before := readOperands(t, ns)
	replicas := ptr.Deref(getCR(t, ns).Spec.TSA.Replicas, 1)
	time.Sleep(2 * time.Second)
	baseline := runtime.NumGoroutine()

	// timeout 0: the connections stay open and every byte is dropped.
	hold := map[string]any{"timeout": 0}
	p.addToxic("silent-down", "timeout", "downstream", hold)
	p.addToxic("silent-up", "timeout", "upstream", hold)
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Replicas = new(replicas + 1) })
	time.Sleep(30 * time.Second)
	sup.requireLeaseLossExit()
	if n := len(sup.exitList()); n != 1 {
		t.Fatalf("%d restarts during a 30 s silent outage, want 1 (the lost lease)", n)
	}
	failed := reqs.failures()
	if len(failed) == 0 {
		t.Fatal("no call failed while the API server was silent")
	}
	// The deadline transport cancels at api_timeout; the renew loop's own
	// deadline is longer, so nothing should outlast api_timeout.
	limit := settings.APITimeout + time.Second
	for _, d := range failed {
		if d > limit {
			t.Errorf("a call failed after %s, past the %s api_timeout", d.Round(time.Millisecond), settings.APITimeout)
		}
	}
	t.Logf("%d calls failed during the outage, slowest %s", len(failed), slowest(failed).Round(time.Millisecond))

	p.removeToxic("silent-down")
	p.removeToxic("silent-up")
	back := time.Now()
	eventually(t, 2*time.Minute, "change made during the outage applied", replicasApplied(ns, replicas+1))
	t.Logf("converged %s after the API server answered again", time.Since(back).Round(time.Millisecond))
	if d := before.diff(readOperands(t, ns)); len(d) > 0 {
		t.Fatalf("operands changed: %v", d)
	}
	sup.requireLeaseLossExit()

	// The incarnation that lost the lease is gone and the new one is
	// settled; a goroutine per abandoned call or watch would show here.
	ceiling := baseline + baseline/10 + 10
	err := poll(time.Minute, func() error {
		if n := runtime.NumGoroutine(); n > ceiling {
			return fmt.Errorf("%d goroutines, baseline %d", n, baseline)
		}
		return nil
	})
	if err != nil {
		var dump bytes.Buffer
		_ = pprof.Lookup("goroutine").WriteTo(&dump, 1)
		t.Fatalf("goroutines did not return to baseline: %v\n%s", err, dump.String())
	}
}

func slowest(ds []time.Duration) time.Duration {
	var m time.Duration
	for _, d := range ds {
		m = max(m, d)
	}
	return m
}

// settled waits until no reconcile is running and the reconcile count has
// held still for 3 s.
func settled(t *testing.T, timeout time.Duration) {
	t.Helper()
	last, since := reconciles(t), time.Now()
	eventually(t, timeout, "reconciles settled", func() error {
		if n := reconciles(t); n != last || activeWorkers(t) > 0 {
			last, since = n, time.Now()
		}
		if time.Since(since) < 3*time.Second {
			return fmt.Errorf("reconciles still running (%v so far)", last)
		}
		return nil
	})
}

// Watch streams cut.
func TestResilienceWatchesCut(t *testing.T) {
	settings := resilienceSettings()
	p := newAPIProxy(t, "cut")
	var reqs requests
	opns := createNamespace(t, "op")
	sup := supervise(t, supervisorOptions{restCfg: reqs.wrap(p.restConfig()), namespace: opns, env: settings})
	ns := createNamespace(t, "cut")
	installReady(t, ns, time.Minute)
	before := readOperands(t, ns)
	replicas := ptr.Deref(getCR(t, ns).Spec.TSA.Replicas, 1)
	ctx := context.Background()
	key := client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}

	time.Sleep(2 * time.Second)
	watches := reqs.watches.Load()
	p.addToxic("cut", "reset_peer", "downstream", map[string]any{"timeout": 0})
	var d appsv1.Deployment
	if err := k8s.Get(ctx, key, &d); err != nil {
		t.Fatal(err)
	}
	if err := k8s.Delete(ctx, &d); err != nil {
		t.Fatal(err)
	}
	var svc corev1.Service
	if err := k8s.Get(ctx, key, &svc); err != nil {
		t.Fatal(err)
	}
	want := svc.Spec.Selector
	drifted := map[string]string{}
	for k := range want {
		drifted[k] = "drifted"
	}
	svc.Spec.Selector = drifted
	if err := k8s.Update(ctx, &svc); err != nil {
		t.Fatal(err)
	}
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Replicas = new(replicas + 1) })
	time.Sleep(5 * time.Second)
	p.removeToxic("cut")

	back := time.Now()
	eventually(t, 2*time.Minute, "Deployment recreated with the new replicas", replicasApplied(ns, replicas+1))
	eventually(t, 2*time.Minute, "Service selector restored", func() error {
		var s corev1.Service
		if err := k8s.Get(ctx, key, &s); err != nil {
			return err
		}
		for k, v := range want {
			if s.Spec.Selector[k] != v {
				return fmt.Errorf("selector %v, want %v", s.Spec.Selector, want)
			}
		}
		return nil
	})
	t.Logf("converged %s after reconnecting", time.Since(back).Round(time.Millisecond))
	// One watch per informer: Secrets, Deployments, Services, ConfigMaps
	// and the instances.
	if n := reqs.watches.Load() - watches; n < 5 {
		t.Fatalf("%d watches opened after the cut, want every informer's (5) cut and reopened", n)
	}
	if n := len(sup.exitList()); n != 0 {
		t.Fatalf("%d restarts for a 5 s cut, want none: %v", n, sup.exitList())
	}
	// Only the Deployment deleted under the operator is new.
	after := readOperands(t, ns)
	dep := "Deployment/" + key.Name
	if after[dep] == before[dep] {
		t.Fatalf("Deployment %s has its old UID; it was not recreated", key.Name)
	}
	before[dep] = after[dep]
	if d := before.diff(after); len(d) > 0 {
		t.Fatalf("operands changed: %v", d)
	}
}

// A slow API server, 2 s added to every response and the
// bandwidth cut.
func TestResilienceSlowAPIServer(t *testing.T) {
	install := func(t *testing.T, name string, slow bool) (float64, int64) {
		settings := resilienceSettings()
		p := newAPIProxy(t, name)
		if slow {
			p.addToxic("latency", "latency", "downstream", map[string]any{"latency": 2000})
			p.addToxic("bandwidth", "bandwidth", "downstream", map[string]any{"rate": 64})
		}
		var reqs requests
		opns := createNamespace(t, "op")
		sup := supervise(t, supervisorOptions{restCfg: reqs.wrap(p.restConfig()), namespace: opns, env: settings})
		eventually(t, 2*time.Minute, "operator leading", func() error {
			if reqs.count.Load() == 0 {
				return fmt.Errorf("no requests yet")
			}
			return nil
		})
		// Instances left by other tests would be reconciled too.
		var all pqcv1alpha1.SecureSignPQCList
		if err := k8s.List(context.Background(), &all); err != nil {
			t.Fatal(err)
		}
		if len(all.Items) != 0 {
			t.Fatalf("%d instances already exist; the counts would include them", len(all.Items))
		}
		// Owned objects outlive their deleted instances (envtest has no
		// garbage collector), and each enqueues a reconcile at start-up.
		settled(t, time.Minute)
		ns := createNamespace(t, name)
		r0, q0 := reconciles(t), reqs.count.Load()
		start := time.Now()
		installReady(t, ns, 10*time.Minute)
		ready := time.Since(start)
		settled(t, 5*time.Minute)
		r, q := reconciles(t)-r0, reqs.count.Load()-q0
		t.Logf("%s: Ready in %s, %v reconciles, %d requests", name, ready.Round(time.Millisecond), r, q)
		if r == 0 {
			t.Fatalf("%s: no reconcile counted", name)
		}
		if n := len(sup.exitList()); n != 0 {
			t.Fatalf("%s: %d restarts: %v", name, n, sup.exitList())
		}
		sup.stop()
		return r, q
	}
	var r, sr float64
	var q, sq int64
	t.Run("fast", func(t *testing.T) { r, q = install(t, "fast", false) })
	t.Run("slow", func(t *testing.T) { sr, sq = install(t, "slow", true) })
	if t.Failed() {
		return
	}
	if sr > 2*r {
		t.Errorf("%v reconciles when slow, over twice the %v unfaulted", sr, r)
	}
	if sq > 2*q {
		t.Errorf("%d requests when slow, over twice the %d unfaulted", sq, q)
	}
}
