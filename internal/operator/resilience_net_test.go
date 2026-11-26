//go:build resilience

package operator

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
)

// reconciles is sup's reconcile count so far, from the controller-runtime
// registry every manager in the process shares.
func reconciles(t *testing.T, sup *supervisor) float64 {
	t.Helper()
	return controllerMetric(t, sup, "controller_runtime_reconcile_total")
}

// activeWorkers is how many of sup's reconciles are running.
func activeWorkers(t *testing.T, sup *supervisor) float64 {
	t.Helper()
	return controllerMetric(t, sup, "controller_runtime_active_workers")
}

// reconcileResults is sup's reconcile count by result.
func reconcileResults(t *testing.T, sup *supervisor) map[string]float64 {
	t.Helper()
	return metricByLabel(t, metrics.Registry, "controller_runtime_reconcile_total", "result", map[string]string{"controller": sup.controller})
}

// reconcileFailures is the operator's failed reconcile count by reason, from
// its supervisor's registry.
func reconcileFailures(t *testing.T, g prometheus.Gatherer) map[string]float64 {
	t.Helper()
	return metricByLabel(t, g, "pqc_operator_reconcile_failures_total", "reason", nil)
}

func metricByLabel(t *testing.T, g prometheus.Gatherer, name, label string, match map[string]string) map[string]float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.Metric {
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			matched := true
			for k, v := range match {
				matched = matched && labels[k] == v
			}
			if matched {
				out[labels[label]] += m.GetCounter().GetValue()
			}
		}
	}
	return out
}

// countsSince is the non-zero growth of each count since before.
func countsSince(now, before map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range now {
		if d := v - before[k]; d != 0 {
			out[k] = d
		}
	}
	return out
}

func controllerMetric(t *testing.T, sup *supervisor, name string) float64 {
	t.Helper()
	return metricValue(t, metrics.Registry, name, map[string]string{"controller": sup.controller})
}

// The API server accepts connections but never answers.
func TestResilienceAPIServerSilent(t *testing.T) {
	freshEnv(t)
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
func settled(t *testing.T, sup *supervisor, timeout time.Duration) {
	t.Helper()
	last, since := reconciles(t, sup), time.Now()
	eventually(t, timeout, "reconciles settled", func() error {
		if n := reconciles(t, sup); n != last || activeWorkers(t, sup) > 0 {
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
	freshEnv(t)
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
	freshEnv(t)
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
		// Counting starts from a quiet operator: leading, with every
		// informer's list in and its watch open.
		holder := leaseHolder(opns)
		eventually(t, 5*time.Minute, "operator leading and synced", func() error {
			if h, err := holder(); err != nil || h != "operator" {
				return fmt.Errorf("lease held by %q: %v", h, err)
			}
			return reqs.watching("securesignpqcs", "deployments", "services", "ingresses", "secrets", "configmaps")
		})
		// An instance left by the fast run would be reconciled too.
		var all pqcv1alpha1.SecureSignPQCList
		if err := k8s.List(context.Background(), &all); err != nil {
			t.Fatal(err)
		}
		if len(all.Items) != 0 {
			t.Fatalf("%d instances already exist; the counts would include them", len(all.Items))
		}
		// Start-up reconciles are not counted.
		settled(t, sup, time.Minute)
		ns := createNamespace(t, name)
		// Lease renewals run at the retry period however long the install
		// takes, so the reconciler's requests are counted without them.
		r0, q0, l0 := reconciles(t, sup), reqs.count.Load(), reqs.leases.Load()
		c0, o0, f0 := reqs.byCall(), reconcileResults(t, sup), reconcileFailures(t, sup.reg)
		start := time.Now()
		installReady(t, ns, 10*time.Minute)
		ready := time.Since(start)
		settled(t, sup, 5*time.Minute)
		l := reqs.leases.Load() - l0
		r, q := reconciles(t, sup)-r0, reqs.count.Load()-q0-l
		t.Logf("%s: Ready in %s, %v reconciles, %d requests and %d lease calls", name, ready.Round(time.Millisecond), r, q, l)
		t.Logf("%s: reconcile results %v, failures %v", name, countsSince(reconcileResults(t, sup), o0), countsSince(reconcileFailures(t, sup.reg), f0))
		t.Logf("%s: requests by call:%s", name, reqs.callsSince(c0))
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
