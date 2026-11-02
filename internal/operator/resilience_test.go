//go:build resilience

package operator

import (
	"fmt"
	"os"
	"testing"
	"time"

	"k8s.io/utils/ptr"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
)

// API server fault scenarios.

// resilienceSettings are the lane's shortened timings.
func resilienceSettings() tuning.Settings {
	s := testSettings()
	s.LeaseDuration, s.RenewDeadline, s.RetryPeriod = 20*time.Second, 15*time.Second, 2*time.Second
	return s
}

// The API server refuses connections.
func TestResilienceAPIServerRefuses(t *testing.T) {
	t.Run("30s", func(t *testing.T) { refusedOutage(t, 30*time.Second) })
	t.Run("10m", func(t *testing.T) {
		if os.Getenv("RESILIENCE_LONG") == "" {
			t.Skip("set RESILIENCE_LONG=1 for the 10-minute outage")
		}
		refusedOutage(t, 10*time.Minute)
	})
}

func refusedOutage(t *testing.T, outage time.Duration) {
	settings := resilienceSettings()
	p := newAPIProxy(t, "refuse-"+t.Name()[len("TestResilienceAPIServerRefuses/"):])
	opns := createNamespace(t, "op")
	sup := supervise(t, supervisorOptions{restCfg: p.restConfig(), namespace: opns, env: settings})
	ns := createNamespace(t, "refuse")
	installReady(t, ns, time.Minute)
	before := readOperands(t, ns)
	replicas := ptr.Deref(getCR(t, ns).Spec.TSA.Replicas, 1)

	p.setEnabled(false)
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Replicas = new(replicas + 1) })
	time.Sleep(outage)
	// The outage outlasts the renew deadline, so the lease is lost once.
	sup.requireLeaseLossExit()
	if n := len(sup.exitList()); n != 1 {
		t.Fatalf("%d restarts during a %s outage, want 1 (the lost lease)", n, outage)
	}

	p.setEnabled(true)
	back := time.Now()
	eventually(t, 2*time.Minute, "change made during the outage applied", replicasApplied(ns, replicas+1))
	recovery := time.Since(back)
	t.Logf("converged %s after the API server returned", recovery.Round(time.Millisecond))
	// The restarted process keeps its pod's identity, so it takes the lease
	// back at once instead of waiting out the one it held before.
	if recovery >= settings.LeaseDuration {
		t.Errorf("recovery took %s, at least the %s lease: the restarted operator waited out its own lease", recovery, settings.LeaseDuration)
	}
	if d := before.diff(readOperands(t, ns)); len(d) > 0 {
		t.Fatalf("operands changed: %v", d)
	}
	sup.requireLeaseLossExit()
}

// A refused-connection outage with the environment's slow production
// timings, overridden through the ConfigMap.
func TestResilienceTunedRecovery(t *testing.T) {
	env := tuning.Defaults()
	p := newAPIProxy(t, "tuned")
	opns := createNamespace(t, "op")
	setTuning(t, opns, map[string]string{
		"backoff_max": "5s", "lease_duration": "6s", "renew_deadline": "4s", "retry_period": "1s",
	})
	sup := supervise(t, supervisorOptions{restCfg: p.restConfig(), namespace: opns, env: env})
	eventually(t, 30*time.Second, "override in effect", func() error {
		if got := configValue(t, sup.reg, "renew_deadline"); got != 4 {
			return fmt.Errorf("renew_deadline %v", got)
		}
		return nil
	})
	ns := createNamespace(t, "tuned")
	installReady(t, ns, time.Minute)
	before := readOperands(t, ns)
	replicas := ptr.Deref(getCR(t, ns).Spec.TSA.Replicas, 1)

	p.setEnabled(false)
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Replicas = new(replicas + 1) })
	time.Sleep(30 * time.Second)
	if n := len(sup.exitList()); n != 1 {
		t.Fatalf("%d restarts, want 1: the overridden 4 s renew deadline must lose the lease", n)
	}
	sup.requireLeaseLossExit()

	p.setEnabled(true)
	back := time.Now()
	eventually(t, 2*time.Minute, "change made during the outage applied", replicasApplied(ns, replicas+1))
	recovery := time.Since(back)
	t.Logf("converged %s after the API server returned", recovery.Round(time.Millisecond))
	// One startup poll interval, then start-up, cache sync and the apply.
	if bound := startupPollMax + 5*time.Second; recovery > bound {
		t.Errorf("recovery took %s, over the %s the startup poll allows", recovery, bound)
	}
	if got := configValue(t, sup.reg, "renew_deadline"); got != 4 {
		t.Errorf("after restart renew_deadline is %v, want the override's 4", got)
	}
	if d := before.diff(readOperands(t, ns)); len(d) > 0 {
		t.Fatalf("operands changed: %v", d)
	}
}
