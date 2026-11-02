//go:build resilience

package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// The operator's ClusterRoleBinding deleted, then restored.
func TestResilienceRBACRemoved(t *testing.T) {
	ctx := context.Background()
	settings := resilienceSettings()
	settings.BackoffMax = 10 * time.Second
	opns := createNamespace(t, "op")
	userCfg, crb := operatorUser(t, opns)
	sup := supervise(t, supervisorOptions{restCfg: userCfg, namespace: opns, env: settings})
	ns := createNamespace(t, "rbac")
	installReady(t, ns, time.Minute)
	before := readOperands(t, ns)
	replicas := ptr.Deref(getCR(t, ns).Spec.TSA.Replicas, 1)
	forbidden := sup.failures("Forbidden")

	if err := k8s.Delete(ctx, crb); err != nil {
		t.Fatal(err)
	}
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Replicas = new(replicas + 1) })
	eventually(t, 30*time.Second, "refusals counted", func() error {
		if sup.failures("Forbidden") <= forbidden {
			return errors.New("no Forbidden failure counted")
		}
		return nil
	})
	// Long enough for the backoff to reach its cap.
	time.Sleep(20 * time.Second)
	if err := replicasApplied(ns, replicas+1)(); err == nil {
		t.Fatal("change applied without the ClusterRoleBinding")
	}
	t.Logf("%v Forbidden failures counted", sup.failures("Forbidden")-forbidden)

	restored := &rbacv1.ClusterRoleBinding{Name: crb.Name, RoleRef: crb.RoleRef, Subjects: crb.Subjects}
	if err := k8s.Create(ctx, restored); err != nil {
		t.Fatal(err)
	}
	back := time.Now()
	eventually(t, 2*time.Minute, "change applied", replicasApplied(ns, replicas+1))
	recovery := time.Since(back)
	t.Logf("converged %s after the binding returned", recovery.Round(time.Millisecond))
	if bound := settings.BackoffMax + 5*time.Second; recovery > bound {
		t.Errorf("recovery took %s, over one %s backoff cap", recovery, settings.BackoffMax)
	}
	if n := len(sup.exitList()); n != 0 {
		t.Fatalf("%d restarts: %v", n, sup.exitList())
	}
	if d := before.diff(readOperands(t, ns)); len(d) > 0 {
		t.Fatalf("operands changed: %v", d)
	}
	// The new replica count is a rollout; play the Deployment controller.
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready and not Degraded", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionReady, "True", ""); err != nil {
			return err
		}
		return conditionIs(cr, pqcv1alpha1.ConditionDegraded, "False", "")
	})
}
