//go:build resilience

package operator

import (
	"context"
	"fmt"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

func leaseHolder(opns string) func() (string, error) {
	return func() (string, error) {
		var l coordinationv1.Lease
		if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: opns, Name: LeaderElectionID}, &l); err != nil {
			return "", err
		}
		return ptr.Deref(l.Spec.HolderIdentity, ""), nil
	}
}

// The leader cut off from the API server.
func TestResilienceLeaderCutOff(t *testing.T) {
	settings := resilienceSettings()
	// Resyncs keep the cut-off leader reconciling until it exits.
	settings.SyncPeriod = 2 * time.Second
	var log writeLog
	opns := createNamespace(t, "op")
	pa, pb := newAPIProxy(t, "leader-a"), newAPIProxy(t, "leader-b")
	a := supervise(t, supervisorOptions{name: "a", restCfg: pa.restConfig(), namespace: opns, env: settings, log: &log})
	holder := leaseHolder(opns)
	eventually(t, time.Minute, "a leading", func() error {
		if h, err := holder(); err != nil || h != "a" {
			return fmt.Errorf("holder %q: %v", h, err)
		}
		return nil
	})
	b := supervise(t, supervisorOptions{name: "b", restCfg: pb.restConfig(), namespace: opns, env: settings, log: &log})
	ns := createNamespace(t, "leader")
	installReady(t, ns, time.Minute)
	before := readOperands(t, ns)
	replicas := ptr.Deref(getCR(t, ns).Spec.TSA.Replicas, 1)

	failed := a.allFailures()
	pa.setEnabled(false)
	cut := time.Now()
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Replicas = new(replicas + 1) })
	eventually(t, 2*time.Minute, "change applied by the standby", replicasApplied(ns, replicas+1))
	t.Logf("change applied %s after the leader was cut off", time.Since(cut).Round(time.Millisecond))
	if h, _ := holder(); h != "b" {
		t.Fatalf("lease holder %q, want b", h)
	}

	exits := a.exitList()
	if len(exits) != 1 {
		t.Fatalf("a exited %d times, want once on losing the lease", len(exits))
	}
	a.requireLeaseLossExit()
	aExit := exits[0].at
	var aLast, bFirst time.Time
	var aWrites, bWrites, aCut int
	for _, w := range log.snapshot() {
		switch {
		case w.manager == "a" && w.namespace == ns:
			aWrites++
			if w.at.After(cut) {
				aCut++
			}
			if w.at.After(aLast) {
				aLast = w.at
			}
		case w.manager == "b" && w.namespace == ns:
			bWrites++
			if bFirst.IsZero() || w.at.Before(bFirst) {
				bFirst = w.at
			}
		}
	}
	if aWrites == 0 || bWrites == 0 {
		t.Fatalf("a made %d writes and b %d; want the install by a and the change by b", aWrites, bWrites)
	}
	t.Logf("a's last write %s after the cut, a exited %s after, b's first write %s after",
		aLast.Sub(cut).Round(time.Millisecond), aExit.Sub(cut).Round(time.Millisecond), bFirst.Sub(cut).Round(time.Millisecond))
	if !aLast.Before(aExit) {
		t.Errorf("a wrote at %s, after exiting at %s", aLast, aExit)
	}
	if !aExit.Before(bFirst) {
		t.Errorf("b first wrote at %s, before a exited at %s: two leaders wrote at once", bFirst, aExit)
	}
	// Its reads fail first, so it may attempt no write at all.
	if a.allFailures() <= failed {
		t.Fatal("a did not reconcile while cut off; the ordering above shows nothing")
	}
	t.Logf("a attempted %d writes while cut off", aCut)

	// Back on the network, the restarted a stays standby.
	pa.setEnabled(true)
	time.Sleep(settings.LeaseDuration)
	if h, _ := holder(); h != "b" {
		t.Fatalf("lease holder %q after a reconnected, want b", h)
	}
	if n := len(a.exitList()); n != 1 {
		t.Fatalf("a exited %d times, want once", n)
	}
	if n := len(b.exitList()); n != 0 {
		t.Fatalf("b exited %d times: %v", n, b.exitList())
	}
	if d := before.diff(readOperands(t, ns)); len(d) > 0 {
		t.Fatalf("operands changed: %v", d)
	}
}
