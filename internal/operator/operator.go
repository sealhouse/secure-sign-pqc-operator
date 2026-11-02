// Package operator assembles the manager: client and leader election
// settings from tuning, the cache scope, the SecureSignPQC controller, the
// effective-settings and reconcile-failure metrics, the tuning ConfigMap
// watcher and the metrics endpoint's certificate and ServiceMonitor.
package operator

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
)

// The tuning ConfigMap and the leader election Lease live in the operator's
// own namespace.
// +kubebuilder:rbac:groups="",namespace=system,resources=configmaps,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups=events.k8s.io,namespace=system,resources=events,verbs=create;patch

// LeaderElectionID names the Lease the operator replicas compete for.
const LeaderElectionID = "rhtas-pqc-operator.pqc.rhtas.redhat.com"

// Options configure Run.
type Options struct {
	Scheme    *runtime.Scheme
	Namespace string // the operator's own namespace
	// Env is the settings from defaults and environment, before the
	// ConfigMap.
	Env tuning.Settings
	// Effective is the settings the manager starts with.
	Effective tuning.Settings
	Profiles  versions.Set
	// Manager carries metrics, webhook and probe options from flags.
	Manager ctrl.Options
	// Metrics describes the metrics endpoint for its ServiceMonitor.
	Metrics        MetricsOptions
	LeaderElection bool
	// LeaderElectionIdentity is the holder name written to the Lease, the
	// pod's name in a cluster.
	LeaderElectionIdentity string
	// Registry receives the pqc_operator_config metric; nil means the
	// controller-runtime registry.
	Registry prometheus.Registerer
}

// NewManager builds the manager and registers everything on it. restart
// is called with tuning settings this manager cannot take.
func NewManager(cfg *rest.Config, o Options, restart func(tuning.Settings)) (manager.Manager, error) {
	s := o.Effective
	live := tuning.NewLive(s)
	managed := labels.SelectorFromSet(labels.Set{controller.LabelManagedBy: controller.ManagedBy})
	mopts := o.Manager
	mopts.Scheme = o.Scheme
	mopts.LeaderElection = o.LeaderElection
	mopts.LeaderElectionID = LeaderElectionID
	mopts.LeaderElectionNamespace = o.Namespace
	mopts.LeaderElectionReleaseOnCancel = true
	mopts.LeaseDuration = &s.LeaseDuration
	mopts.RenewDeadline = &s.RenewDeadline
	mopts.RetryPeriod = &s.RetryPeriod
	mopts.Cache = cache.Options{
		SyncPeriod: &s.SyncPeriod,
		ByObject: map[client.Object]cache.ByObject{
			// Only objects the operator labels are cached, so a cluster's
			// other Secrets never enter its memory.
			&corev1.Secret{}:        {Label: managed},
			&appsv1.Deployment{}:    {Label: managed},
			&corev1.Service{}:       {Label: managed},
			&networkingv1.Ingress{}: {Label: managed},
			// The tuning ConfigMap, and the metrics CA ConfigMap.
			&corev1.ConfigMap{}: {Namespaces: map[string]cache.Config{o.Namespace: {}}},
		},
	}
	if o.Metrics.Service != "" {
		addMetricsCaches(mopts.Cache.ByObject)
	}
	if o.LeaderElection && o.LeaderElectionIdentity != "" {
		lock, err := resourcelock.NewFromKubeconfig(resourcelock.LeasesResourceLock, o.Namespace, LeaderElectionID,
			resourcelock.ResourceLockConfig{Identity: o.LeaderElectionIdentity}, RestConfig(cfg, live), s.RenewDeadline)
		if err != nil {
			return nil, fmt.Errorf("leader election lock: %w", err)
		}
		mopts.LeaderElectionResourceLockInterface = lock
	}
	if mopts.HealthProbeBindAddress == "" {
		mopts.HealthProbeBindAddress = "0"
	}
	var cert *metricsCert
	if o.Metrics.Secure && o.Metrics.CertFile != "" {
		var err error
		if cert, err = newMetricsCert(o.Metrics.CertFile, o.Metrics.KeyFile); err != nil {
			return nil, err
		}
		mopts.Metrics.TLSOpts = append(slices.Clone(mopts.Metrics.TLSOpts), func(c *tls.Config) {
			c.GetCertificate = cert.GetCertificate
		})
	}

	mgr, err := ctrl.NewManager(RestConfig(cfg, live), mopts)
	if err != nil {
		return nil, err
	}

	reg := o.Registry
	if reg == nil {
		reg = metrics.Registry
	}
	configMetric, err := registerConfigMetric(reg, s)
	if err != nil {
		return nil, err
	}
	failures, err := registerFailureMetric(reg)
	if err != nil {
		return nil, err
	}

	recorder := mgr.GetEventRecorder(controller.ManagedBy)
	if err := (&controller.SecureSignPQCReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Recorder:  recorder,
		Profiles:  o.Profiles,
		Settings:  live,
		Failures:  failures,
	}).SetupWithManager(mgr); err != nil {
		return nil, fmt.Errorf("controller: %w", err)
	}

	if err := mgr.Add(&configWatcher{
		cache:     mgr.GetCache(),
		namespace: o.Namespace,
		env:       o.Env,
		live:      live,
		metric:    configMetric,
		recorder:  recorder,
		restart:   restart,
	}); err != nil {
		return nil, err
	}

	if o.Metrics.Service != "" {
		if err := (&serviceMonitorReconciler{
			mgr:       mgr,
			client:    mgr.GetClient(),
			reader:    mgr.GetAPIReader(),
			namespace: o.Namespace,
			opts:      o.Metrics,
			cert:      cert,
		}).setup(mgr); err != nil {
			return nil, fmt.Errorf("metrics controller: %w", err)
		}
	}
	if cert != nil {
		if err := mgr.Add(cert); err != nil {
			return nil, err
		}
	}

	// Liveness and readiness never call the API server, so an API outage
	// does not get the operator killed.
	if mopts.HealthProbeBindAddress != "0" {
		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			return nil, err
		}
		if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
			return nil, err
		}
	}
	return mgr, nil
}

// Run runs the operator until ctx ends or its manager fails. Tuning
// settings a running manager cannot take replace it with a new one, in this
// process.
func Run(ctx context.Context, cfg *rest.Config, o Options) error {
	for {
		next, err := runManager(ctx, cfg, o)
		if next == nil || ctx.Err() != nil {
			return err
		}
		o.Effective = *next
		// The first manager's controllers keep their names registered.
		o.Manager.Controller.SkipNameValidation = new(true)
		logf.FromContext(ctx).Info("Restarting the manager with new tuning settings", "settings", next.Values())
	}
}

// runManager runs one manager, returning the settings to restart with if it
// stopped for them.
func runManager(ctx context.Context, cfg *rest.Config, o Options) (*tuning.Settings, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var next atomic.Pointer[tuning.Settings]
	mgr, err := NewManager(cfg, o, func(s tuning.Settings) { next.Store(&s); cancel() })
	if err != nil {
		return nil, err
	}
	err = mgr.Start(ctx)
	if s := next.Load(); s != nil {
		return s, nil
	}
	return nil, err
}

// registerConfigMetric registers the pqc_operator_config gauge, or reuses
// the one a previous manager in this process registered.
func registerConfigMetric(reg prometheus.Registerer, s tuning.Settings) (*prometheus.GaugeVec, error) {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pqc_operator_config",
		Help: "Effective operator tuning settings; durations in seconds.",
	}, []string{"setting"})
	if err := reg.Register(g); err != nil {
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			return nil, err
		}
		g = are.ExistingCollector.(*prometheus.GaugeVec)
	}
	setConfigMetric(g, s)
	return g, nil
}

func setConfigMetric(g *prometheus.GaugeVec, s tuning.Settings) {
	g.Reset()
	for k, v := range s.Values() {
		g.WithLabelValues(k).Set(v)
	}
}

// registerFailureMetric registers the reconcile failure counter, or returns
// the one already registered, so counts carry over a restart within one
// process.
func registerFailureMetric(reg prometheus.Registerer) (*prometheus.CounterVec, error) {
	c := controller.NewFailureCounter()
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			return nil, err
		}
		return are.ExistingCollector.(*prometheus.CounterVec), nil
	}
	return c, nil
}
