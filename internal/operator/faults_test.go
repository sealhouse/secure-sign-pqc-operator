package operator

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

// faults injects API errors into the manager's client.
type faults struct {
	mu sync.Mutex
	// deploymentApply, when set, is returned by every Deployment apply.
	deploymentApply error
	applies         atomic.Int32
	// statusApply, when set, makes every status apply, given as apply.
	statusApply func(apply func() error) error
}

func (f *faults) set(err error) {
	f.mu.Lock()
	f.deploymentApply = err
	f.mu.Unlock()
}

// withWatch gives the manager's cache-backed client the Watch method the
// interceptor needs; Watch itself is never intercepted here.
type withWatch struct {
	client.Client
	w client.WithWatch
}

func (c withWatch) Watch(ctx context.Context, list client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
	return c.w.Watch(ctx, list, opts...)
}

func (f *faults) newClient(cfg *rest.Config, opts client.Options) (client.Client, error) {
	c, err := client.New(cfg, opts)
	if err != nil {
		return nil, err
	}
	w, err := client.NewWithWatch(cfg, client.Options{Scheme: opts.Scheme, Mapper: opts.Mapper})
	if err != nil {
		return nil, err
	}
	return interceptor.NewClient(withWatch{c, w}, interceptor.Funcs{
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			if _, ok := obj.(*appsv1ac.DeploymentApplyConfiguration); ok {
				f.applies.Add(1)
				f.mu.Lock()
				err := f.deploymentApply
				f.mu.Unlock()
				if err != nil {
					return err
				}
			}
			return c.Apply(ctx, obj, opts...)
		},
		SubResourceApply: func(ctx context.Context, c client.Client, sub string, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
			apply := func() error { return c.SubResource(sub).Apply(ctx, obj, opts...) }
			f.mu.Lock()
			hook := f.statusApply
			f.mu.Unlock()
			if hook != nil {
				return hook(apply)
			}
			return apply()
		},
	}), nil
}

var deployments = schema.GroupResource{Group: "apps", Resource: "deployments"}

// 403, 409, 429, 500, 503 and 504 responses.
func TestAPIErrorsDegradeAndRecover(t *testing.T) {
	ctx := context.Background()
	f := &faults{}
	startOperator(t, createNamespace(t, "op"), func(o *Options) { o.Manager.NewClient = f.newClient })

	for _, tc := range []struct {
		code   int
		err    error
		reason string
	}{
		{429, apierrors.NewTooManyRequests("injected", 1), "TooManyRequests"},
		{500, apierrors.NewInternalError(fmt.Errorf("injected")), "InternalError"},
		{503, apierrors.NewServiceUnavailable("injected"), "ServiceUnavailable"},
		{504, apierrors.NewTimeoutError("injected", 1), "Timeout"},
		{403, apierrors.NewForbidden(deployments, "demo-tsa", fmt.Errorf("injected")), "Forbidden"},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			ns := createNamespace(t, fmt.Sprintf("err%d", tc.code))
			f.set(tc.err)
			if err := k8s.Create(ctx, newInstance(ns)); err != nil {
				t.Fatal(err)
			}
			eventually(t, 30*time.Second, "Degraded", func() error {
				return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionDegraded, metav1.ConditionTrue, tc.reason)
			})
			// Nothing was deleted: the signer was created before the
			// failing write and is still the only one.
			first := signerSecret(t, ns, 1)

			f.set(nil)
			markAvailable(t, ns)
			eventually(t, 30*time.Second, "recovered", func() error {
				cr := getCR(t, ns)
				if err := conditionIs(cr, pqcv1alpha1.ConditionDegraded, metav1.ConditionFalse, ""); err != nil {
					return err
				}
				return conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
			})
			if signerSecret(t, ns, 1).UID != first.UID {
				t.Fatal("signer Secret replaced during the fault")
			}
		})
	}

	t.Run("409", func(t *testing.T) {
		ns := createNamespace(t, "err409")
		f.set(apierrors.NewConflict(deployments, "demo-tsa", fmt.Errorf("injected")))
		start := f.applies.Load()
		if err := k8s.Create(ctx, newInstance(ns)); err != nil {
			t.Fatal(err)
		}
		// Let well over DegradedAfter attempts happen.
		eventually(t, 30*time.Second, "retries", func() error {
			if n := f.applies.Load() - start; n < 6 {
				return fmt.Errorf("%d attempts", n)
			}
			return nil
		})
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionDegraded, metav1.ConditionTrue, ""); err == nil {
			t.Fatal("conflicts marked the instance Degraded")
		}
		f.set(nil)
		markAvailable(t, ns)
		eventually(t, 30*time.Second, "Ready after conflicts", func() error {
			return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
		})
	})
}

// A refused spec ends the failing passes, so it clears Degraded.
func TestBlockedClearsDegraded(t *testing.T) {
	ctx := context.Background()
	f := &faults{}
	startOperator(t, createNamespace(t, "op"), func(o *Options) { o.Manager.NewClient = f.newClient })
	ns := createNamespace(t, "blocked")
	f.set(apierrors.NewInternalError(fmt.Errorf("injected")))
	cr := newInstance(ns)
	cr.Spec.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA87
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "Degraded", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionDegraded, metav1.ConditionTrue, "InternalError")
	})

	// The weaker key is refused before the failing Deployment apply.
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) {
		s.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA44
		s.TSA.Signing.AcceptWeakerAlgorithm = &pqcv1alpha1.WeakerAlgorithmAcceptance{Algorithm: pqcv1alpha1.MLDSA44, SignerGeneration: 2}
	})
	// Admission only checks the acceptance when the algorithm changes.
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.AcceptWeakerAlgorithm.SignerGeneration = 3 })
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.SignerGeneration = 2 })
	eventually(t, 30*time.Second, "blocked and not Degraded", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "WeakerAlgorithmNotAccepted"); err != nil {
			return err
		}
		return conditionIs(cr, pqcv1alpha1.ConditionDegraded, metav1.ConditionFalse, "")
	})
}

// The requeue backoff is capped at BackoffMax rather than controller-runtime's
// 1000 s default, so a persistent fault is retried at least once per cap.
func TestBackoffCap(t *testing.T) {
	ctx := context.Background()
	f := &faults{}
	f.set(apierrors.NewServiceUnavailable("injected"))
	// The cap comes from the ConfigMap, over an environment that says 60 s.
	opns := createNamespace(t, "op")
	setTuning(t, opns, map[string]string{"backoff_max": "500ms"})
	env := testSettings()
	env.BackoffMax = time.Minute
	effective, err := LoadTuning(ctx, cfg, scheme, opns, env)
	if err != nil {
		t.Fatal(err)
	}
	startOperator(t, opns, func(o *Options) {
		o.Manager.NewClient = f.newClient
		o.Env, o.Effective = env, effective
	})
	ns := createNamespace(t, "cap")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	// Uncapped, attempts 10 to 20 would take 2.5 s to 45 min.
	eventually(t, 5*time.Second, "warm-up", func() error {
		if f.applies.Load() < 10 {
			return fmt.Errorf("%d attempts", f.applies.Load())
		}
		return nil
	})
	before := f.applies.Load()
	time.Sleep(5 * time.Second)
	if got := f.applies.Load() - before; got < 8 {
		t.Fatalf("%d attempts in 5 s with a 500 ms cap", got)
	}
}

func warningFor(ctx context.Context, ns, name, reason string) (bool, error) {
	var list eventsv1.EventList
	if err := k8s.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return false, err
	}
	for _, e := range list.Items {
		if e.Regarding.Kind == "ConfigMap" && e.Regarding.Name == name && e.Reason == reason && e.Type == corev1.EventTypeWarning {
			return true, nil
		}
	}
	return false, nil
}

func setTuning(t *testing.T, ns string, data map[string]string) {
	t.Helper()
	ctx := context.Background()
	cm := &corev1.ConfigMap{Namespace: ns, Name: tuning.ConfigMapName}
	err := k8s.Get(ctx, client.ObjectKeyFromObject(cm), cm)
	switch {
	case apierrors.IsNotFound(err):
		cm.Data = data
		err = k8s.Create(ctx, cm)
	case err == nil:
		cm.Data = data
		err = k8s.Update(ctx, cm)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// An invalid ConfigMap leaves the settings unchanged and records a Warning
// event. A valid change to live settings applies in place; one to a setting
// fixed in the manager asks once for a new manager with it.
func TestTuningConfigMap(t *testing.T) {
	ctx := context.Background()
	opns := createNamespace(t, "op")
	r := startOperator(t, opns, nil)
	eventually(t, 10*time.Second, "pqc_operator_config metric", configValueIs(t, r.reg, "backoff_max", testSettings().BackoffMax.Seconds()))

	setTuning(t, opns, map[string]string{"backoff_max": "soon"})
	eventually(t, 10*time.Second, "Warning event", func() error {
		ok, err := warningFor(ctx, opns, tuning.ConfigMapName, "InvalidTuning")
		if err == nil && !ok {
			err = fmt.Errorf("no InvalidTuning event")
		}
		return err
	})

	setTuning(t, opns, map[string]string{"backoff_max": "5s", "degraded_after": "4"})
	eventually(t, 10*time.Second, "live settings applied", configValueIs(t, r.reg, "backoff_max", 5))
	if got := configValue(t, r.reg, "degraded_after"); got != 4 {
		t.Fatalf("degraded_after %v, want 4", got)
	}
	if n := r.restarts.Load(); n != 0 {
		t.Fatalf("live settings restarted the manager %d times", n)
	}

	setTuning(t, opns, map[string]string{"backoff_max": "5s", "concurrent_reconciles": "2"})
	eventually(t, 10*time.Second, "restart", func() error {
		if r.restarts.Load() == 0 {
			return fmt.Errorf("no restart")
		}
		return nil
	})
	if next := r.next.Load(); next.ConcurrentReconciles != 2 || next.BackoffMax != 5*time.Second {
		t.Fatalf("restart with %+v", next)
	}
	setTuning(t, opns, map[string]string{"backoff_max": "6s", "concurrent_reconciles": "3"})
	time.Sleep(time.Second)
	if n := r.restarts.Load(); n != 1 {
		t.Fatalf("%d restarts, want exactly 1", n)
	}

	// A ConfigMap matching the running settings changes nothing.
	opns2 := createNamespace(t, "op")
	setTuning(t, opns2, map[string]string{"backoff_max": "1s"})
	r2 := startOperator(t, opns2, nil)
	time.Sleep(2 * time.Second)
	if n := r2.restarts.Load(); n != 0 {
		t.Fatalf("ConfigMap equal to the running settings restarted the operator %d times", n)
	}
}

// Run replaces its manager in the same process for a setting the manager
// cannot change, and keeps running.
func TestRunRestartsInProcess(t *testing.T) {
	opns := createNamespace(t, "op")
	profiles, err := supported.Load()
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, Options{
			Scheme: scheme, Namespace: opns, Env: testSettings(), Effective: testSettings(), Profiles: profiles,
			Manager: ctrl.Options{
				Metrics:    metricsserver.Options{BindAddress: "0"},
				Controller: config.Controller{SkipNameValidation: new(true)},
			},
			Registry: reg,
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("Run did not return")
		}
	})
	eventually(t, 10*time.Second, "first manager", configValueIs(t, reg, "concurrent_reconciles", 1))
	setTuning(t, opns, map[string]string{"concurrent_reconciles": "2"})
	eventually(t, 30*time.Second, "second manager", configValueIs(t, reg, "concurrent_reconciles", 2))

	// The new manager reconciles.
	ns := createNamespace(t, "restarted")
	if err := k8s.Create(context.Background(), newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "signer issued by the new manager", func() error {
		return k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1)}, &corev1.Secret{})
	})
	select {
	case err := <-done:
		t.Fatalf("Run returned %v", err)
	default:
	}
}

// A pass that read an instance since deleted does not write its status onto
// one recreated under the same name.
func TestStatusNotWrittenToRecreatedInstance(t *testing.T) {
	ctx := context.Background()
	f := &faults{}
	held, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var first atomic.Bool
	f.statusApply = func(apply func() error) error {
		if !first.CompareAndSwap(false, true) {
			return apply()
		}
		close(held)
		<-release
		err := apply()
		result <- err
		return err
	}
	startOperator(t, createNamespace(t, "op"), func(o *Options) { o.Manager.NewClient = f.newClient })
	ns := createNamespace(t, "recreated")
	old := newInstance(ns)
	if err := k8s.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	select {
	case <-held:
	case <-time.After(30 * time.Second):
		t.Fatal("no status apply")
	}
	if err := k8s.Delete(ctx, old); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "instance gone", gone(old))
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !apierrors.IsConflict(err) {
		t.Fatalf("stale status apply: %v, want a conflict", err)
	}
	eventually(t, 30*time.Second, "recreated instance progressing", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "ComponentsProgressing")
	})
}

// observedAt fails unless each condition type is set at generation gen.
func observedAt(cr *pqcv1alpha1.SecureSignPQC, gen int64, types ...string) error {
	for _, typ := range types {
		c := meta.FindStatusCondition(cr.Status.Conditions, typ)
		if c == nil {
			return fmt.Errorf("no %s condition", typ)
		}
		if c.ObservedGeneration != gen {
			return fmt.Errorf("%s observed at generation %d, want %d", typ, c.ObservedGeneration, gen)
		}
	}
	return nil
}

// Every condition a pass sets records the generation that pass acted on:
// a rollout, a failing pass and a blocked spec.
func TestConditionsObserveTheirGeneration(t *testing.T) {
	ctx := context.Background()
	f := &faults{}
	startOperator(t, createNamespace(t, "op"), func(o *Options) { o.Manager.NewClient = f.newClient })
	ns := createNamespace(t, "observed")
	cr := newInstance(ns)
	cr.Spec.TSA.Ingress = pqcv1alpha1.IngressSpec{Enabled: true, Host: "tsa.example.com"}
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready, every condition at generation 1", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, ""); err != nil {
			return err
		}
		return observedAt(cr, cr.Generation, pqcv1alpha1.ConditionReady, pqcv1alpha1.ConditionTSAReady,
			pqcv1alpha1.ConditionDegraded, pqcv1alpha1.ConditionCertificatesExpiring, pqcv1alpha1.ConditionTSAIngressReady)
	})

	f.set(apierrors.NewInternalError(fmt.Errorf("injected")))
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Replicas = new(int32(2)) })
	eventually(t, 30*time.Second, "Degraded at generation 2", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionDegraded, metav1.ConditionTrue, "InternalError"); err != nil {
			return err
		}
		return observedAt(cr, cr.Generation, pqcv1alpha1.ConditionDegraded)
	})
	f.set(nil)

	eventually(t, 10*time.Second, "blocking edit", func() error {
		cr := getCR(t, ns)
		cr.Spec.TSA.Replicas = new(int32(3))
		cr.Annotations = map[string]string{pqcv1alpha1.FIPSAnnotation: "sometimes"}
		return k8s.Update(ctx, cr)
	})
	eventually(t, 30*time.Second, "blocked at generation 3", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "InvalidFIPSMode"); err != nil {
			return err
		}
		return observedAt(cr, cr.Generation, pqcv1alpha1.ConditionReady, pqcv1alpha1.ConditionDegraded)
	})
}
