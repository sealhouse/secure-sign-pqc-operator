//go:build resilience

package operator

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

// write is one write the operator's client attempted.
type write struct {
	manager   string
	verb      string // create, update, patch, apply, delete, status
	kind      string
	namespace string
	name      string
	at        time.Time
}

func (w write) String() string {
	return fmt.Sprintf("%s %s %s/%s", w.verb, w.kind, w.namespace, w.name)
}

// same reports whether o is the same write to the same object as w.
func (w write) same(o write) bool {
	return w.verb == o.verb && w.kind == o.kind && w.namespace == o.namespace && w.name == o.name
}

// writeHooks run around every write of the operator's client.
type writeHooks struct {
	before func(write) error
	after  func(write, error) error
}

var errFenced = errors.New("operator process has exited")

// newFencedClient returns a Manager.NewClient that records each write
// attempt not fenced in log (if set), passes it through hooks (if set), and refuses
// every write once dead is set.
func newFencedClient(manager string, dead *atomic.Bool, log *writeLog, hooks *writeHooks) client.NewClientFunc {
	return func(cfg *rest.Config, opts client.Options) (client.Client, error) {
		c, err := client.New(cfg, opts)
		if err != nil {
			return nil, err
		}
		w, err := client.NewWithWatch(cfg, client.Options{Scheme: opts.Scheme, Mapper: opts.Mapper})
		if err != nil {
			return nil, err
		}
		describe := func(verb string, obj client.Object) write {
			kind := fmt.Sprintf("%T", obj)
			if gvk, err := apiutil.GVKForObject(obj, opts.Scheme); err == nil {
				kind = gvk.Kind
			}
			return write{manager: manager, verb: verb, kind: kind, namespace: obj.GetNamespace(), name: obj.GetName(), at: time.Now()}
		}
		do := func(wr write, send func() error) error {
			if dead.Load() {
				return errFenced
			}
			// Only writes that may reach the wire: a fenced one never does.
			if log != nil {
				log.add(wr)
			}
			if hooks != nil && hooks.before != nil {
				if err := hooks.before(wr); err != nil {
					return err
				}
			}
			err := send()
			if hooks != nil && hooks.after != nil {
				err = hooks.after(wr, err)
			}
			return err
		}
		return interceptor.NewClient(withWatch{c, w}, interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				return do(describe("create", obj), func() error { return c.Create(ctx, obj, opts...) })
			},
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				return do(describe("update", obj), func() error { return c.Update(ctx, obj, opts...) })
			},
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				return do(describe("patch", obj), func() error { return c.Patch(ctx, obj, patch, opts...) })
			},
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				return do(describe("delete", obj), func() error { return c.Delete(ctx, obj, opts...) })
			},
			DeleteAllOf: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
				return do(describe("deleteallof", obj), func() error { return c.DeleteAllOf(ctx, obj, opts...) })
			},
			Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
				wr := write{manager: manager, verb: "apply", kind: fmt.Sprintf("%T", obj), at: time.Now()}
				if a, ok := obj.(interface {
					GetKind() *string
					GetName() *string
					GetNamespace() *string
				}); ok {
					wr.kind, wr.name, wr.namespace = ptr.Deref(a.GetKind(), wr.kind), ptr.Deref(a.GetName(), ""), ptr.Deref(a.GetNamespace(), "")
				}
				return do(wr, func() error { return c.Apply(ctx, obj, opts...) })
			},
			SubResourceCreate: func(ctx context.Context, c client.Client, sub string, obj, subObj client.Object, opts ...client.SubResourceCreateOption) error {
				return do(describe(sub, obj), func() error { return c.SubResource(sub).Create(ctx, obj, subObj, opts...) })
			},
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				return do(describe(sub, obj), func() error { return c.SubResource(sub).Update(ctx, obj, opts...) })
			},
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				return do(describe(sub, obj), func() error { return c.SubResource(sub).Patch(ctx, obj, patch, opts...) })
			},
			SubResourceApply: func(ctx context.Context, c client.Client, sub string, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
				a, ok := obj.(interface {
					GetKind() string
					GetName() string
					GetNamespace() string
				})
				if !ok {
					return fmt.Errorf("unexpected status apply %T", obj)
				}
				wr := write{manager: manager, verb: sub, kind: a.GetKind(), namespace: a.GetNamespace(), name: a.GetName(), at: time.Now()}
				return do(wr, func() error { return c.SubResource(sub).Apply(ctx, obj, opts...) })
			},
		}), nil
	}
}

// writeLog collects write attempts from one or more managers.
type writeLog struct {
	mu     sync.Mutex
	writes []write
}

func (l *writeLog) add(w write) {
	l.mu.Lock()
	l.writes = append(l.writes, w)
	l.mu.Unlock()
}

func (l *writeLog) snapshot() []write {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.writes)
}

// exit is one return of the operator's Run.
type exit struct {
	at  time.Time
	err error
}

// supervisor plays the kubelet for one operator container: it runs the
// binary's startup path (LoadTuning, then Run, with leader election) and
// starts it again whenever it returns, recording every exit.
type supervisor struct {
	t      *testing.T
	name   string
	reg    *prometheus.Registry
	cancel context.CancelFunc
	done   chan struct{}

	mu    sync.Mutex
	exits []exit
	// kill ends the running incarnation as a crash would.
	kill func()
}

type supervisorOptions struct {
	name      string
	restCfg   *rest.Config
	namespace string
	env       tuning.Settings
	log       *writeLog
	hooks     *writeHooks
	// edit adjusts each incarnation's options.
	edit func(*Options)
}

func supervise(t *testing.T, so supervisorOptions) *supervisor {
	t.Helper()
	if so.name == "" {
		so.name = "operator"
	}
	profiles, err := supported.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &supervisor{t: t, name: so.name, reg: prometheus.NewRegistry(), cancel: cancel, done: make(chan struct{})}
	log := logf.Log.WithName(so.name)
	go func() {
		defer close(s.done)
		for ctx.Err() == nil {
			effective, err := LoadTuning(logf.IntoContext(ctx, log), so.restCfg, scheme, so.namespace, so.env)
			if err != nil {
				return // only when ctx ends
			}
			dead := &atomic.Bool{}
			o := Options{
				Scheme:    scheme,
				Namespace: so.namespace,
				Env:       so.env,
				Effective: effective,
				Profiles:  profiles,
				Manager: ctrl.Options{
					Metrics:    metricsserver.Options{BindAddress: "0"},
					Controller: config.Controller{SkipNameValidation: new(true)},
					NewClient:  newFencedClient(so.name, dead, so.log, so.hooks),
				},
				LeaderElection: true,
				// Each supervisor is one pod: its restarts keep the name.
				LeaderElectionIdentity: so.name,
				Registry:               s.reg,
			}
			if so.edit != nil {
				so.edit(&o)
			}
			ictx, icancel := context.WithCancel(ctx)
			var crashed atomic.Bool
			s.mu.Lock()
			s.kill = func() { crashed.Store(true); dead.Store(true); icancel() }
			s.mu.Unlock()
			err = Run(ictx, so.restCfg, o)
			icancel()
			dead.Store(true)
			if crashed.Load() && ctx.Err() == nil {
				err = errCrashed
			}
			if ctx.Err() != nil {
				return
			}
			log.Info("operator exited; restarting", "error", fmt.Sprint(err))
			s.mu.Lock()
			s.exits = append(s.exits, exit{at: time.Now(), err: err})
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(30 * time.Second):
			t.Errorf("%s did not stop", so.name)
		}
	})
	return s
}

func (s *supervisor) exitList() []exit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.exits)
}

var errCrashed = errors.New("crashed")

// crash ends the running incarnation at once: from this call no write of
// its lands, and it exits with errCrashed.
func (s *supervisor) crash() {
	s.mu.Lock()
	kill := s.kill
	s.mu.Unlock()
	if kill != nil {
		kill()
	}
}

// stop ends the supervised operator, as deleting its pod would.
func (s *supervisor) stop() {
	s.cancel()
	<-s.done
}

// requireLeaseLossExit fails unless the operator has exited at most once, on
// losing its lease: the only restart allowed during an outage.
func (s *supervisor) requireLeaseLossExit() {
	s.t.Helper()
	exits := s.exitList()
	for _, e := range exits {
		if e.err == nil || e.err.Error() != "leader election lost" {
			s.t.Fatalf("%s exited with %v; only a lost lease may end it", s.name, e.err)
		}
	}
	if len(exits) > 1 {
		s.t.Fatalf("%s restarted %d times, want at most once", s.name, len(exits))
	}
}

// failures returns the reconcile failure counter for reason.
func (s *supervisor) failures(reason string) float64 {
	return metricValue(s.t, s.reg, "pqc_operator_reconcile_failures_total", map[string]string{"reason": reason})
}

// allFailures returns the reconcile failure counter across every reason.
func (s *supervisor) allFailures() float64 {
	return metricValue(s.t, s.reg, "pqc_operator_reconcile_failures_total", nil)
}

// operandState is what an outage must not change: the UID of every object
// the operator made for the instance, and the TSA pod template's signer
// hash, which a rollout would change.
type operandState map[string]string

func readOperands(t *testing.T, ns string) operandState {
	t.Helper()
	ctx := context.Background()
	out := operandState{}
	var secrets corev1.SecretList
	if err := k8s.List(ctx, &secrets, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets.Items {
		out["Secret/"+s.Name] = string(s.UID)
	}
	var services corev1.ServiceList
	if err := k8s.List(ctx, &services, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	for _, s := range services.Items {
		out["Service/"+s.Name] = string(s.UID)
	}
	var deployments appsv1.DeploymentList
	if err := k8s.List(ctx, &deployments, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	for _, d := range deployments.Items {
		out["Deployment/"+d.Name] = string(d.UID)
		out["Deployment/"+d.Name+"#signer-hash"] = d.Spec.Template.Annotations[controller.TSASignerHashAnnotation]
	}
	return out
}

func (a operandState) diff(b operandState) []string {
	var out []string
	for k, v := range a {
		if b[k] != v {
			out = append(out, fmt.Sprintf("%s: %q -> %q", k, v, b[k]))
		}
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			out = append(out, fmt.Sprintf("%s: added %q", k, v))
		}
	}
	slices.Sort(out)
	return out
}

// installReady creates the demo instance in ns and waits for Ready.
func installReady(t *testing.T, ns string, timeout time.Duration) {
	t.Helper()
	cr := newInstance(ns)
	if err := k8s.Create(context.Background(), cr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteInstance(t, cr) })
	eventually(t, timeout, "TSA Deployment", func() error {
		return k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &appsv1.Deployment{})
	})
	markAvailable(t, ns)
	eventually(t, timeout, "Ready", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, "True", "")
	})
}

// deleteInstance deletes an instance and the objects it made.
func deleteInstance(t *testing.T, cr *pqcv1alpha1.SecureSignPQC) {
	t.Helper()
	ctx := context.Background()
	if err := client.IgnoreNotFound(k8s.Delete(ctx, cr)); err != nil {
		t.Error(err)
	}
	// The key Secrets are watched too, mapped to their instance by label.
	own := client.MatchingLabels{controller.LabelInstance: cr.Name}
	for _, obj := range []client.Object{&appsv1.Deployment{}, &corev1.Service{}, &corev1.Secret{}} {
		if err := k8s.DeleteAllOf(ctx, obj, client.InNamespace(cr.Namespace), own); err != nil {
			t.Error(err)
		}
	}
}

// replicasApplied waits until the TSA Deployment asks for n replicas.
func replicasApplied(ns string, n int32) func() error {
	return func() error {
		var d appsv1.Deployment
		if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); err != nil {
			return err
		}
		if got := ptr.Deref(d.Spec.Replicas, 1); got != n {
			return fmt.Errorf("replicas %d, want %d", got, n)
		}
		return nil
	}
}
