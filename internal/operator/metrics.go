package operator

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	certutil "k8s.io/client-go/util/cert"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
)

// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,resourceNames=servicemonitors.monitoring.coreos.com,verbs=get;list;watch
// +kubebuilder:rbac:groups="",namespace=system,resources=secrets,verbs=create;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=configmaps,verbs=delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,namespace=system,resources=servicemonitors,verbs=get;list;watch;create;patch

const (
	serviceMonitorCRD = "servicemonitors.monitoring.coreos.com"
	// injectCABundleAnnotation has OpenShift's service-ca write its CA
	// certificate into a ConfigMap, under serviceCAKey.
	injectCABundleAnnotation = "service.beta.openshift.io/inject-cabundle"
	serviceCAKey             = "service-ca.crt"
)

var serviceMonitorGVK = schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}

// MetricsOptions describe the metrics endpoint for the ServiceMonitor the
// operator creates when the Prometheus Operator's API is served.
type MetricsOptions struct {
	// Service is the metrics Service in the operator's namespace; empty
	// creates no ServiceMonitor.
	Service string
	// Scraper is the ServiceAccount whose token Prometheus presents.
	Scraper string
	// Secure is HTTPS with token authentication, rather than plain HTTP.
	Secure bool
	// CertFile and KeyFile are where the service-ca serving certificate
	// is mounted, or empty.
	CertFile, KeyFile string
}

func (o MetricsOptions) token() string { return o.Scraper + "-token" }
func (o MetricsOptions) ca() string    { return o.Service + "-ca" }

// addMetricsCaches limits the CRD cache to the ServiceMonitor CRD.
func addMetricsCaches(byObject map[client.Object]cache.ByObject) {
	byObject[&apiextensionsv1.CustomResourceDefinition{}] = cache.ByObject{
		Field: fields.OneTermEqualSelector("metadata.name", serviceMonitorCRD),
	}
}

// serviceMonitorReconciler keeps a ServiceMonitor for the operator's metrics
// Service, with the scraper's token Secret and, for a service-ca
// certificate, the CA ConfigMap Prometheus verifies it with. All three are
// owned by the Service. It watches the ServiceMonitor CRD, and the
// ServiceMonitor itself while the CRD is established. When the CRD goes, it
// stops that watch and deletes the token Secret and CA ConfigMap.
type serviceMonitorReconciler struct {
	mgr       ctrl.Manager
	client    client.Client
	reader    client.Reader
	namespace string
	opts      MetricsOptions
	// cert is the endpoint's certificate, nil when none is mounted.
	cert *metricsCert

	ctrl ctrlcontroller.Controller
	// smCache and watching are only touched by the controller's one worker.
	smCache  cache.Cache
	watching bool
}

// toCRD maps every watched object to the one request, keyed by the CRD.
var toCRD = handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
	return []reconcile.Request{{Name: serviceMonitorCRD}}
})

func (r *serviceMonitorReconciler) named(name string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetNamespace() == r.namespace && o.GetName() == name
	})
}

func (r *serviceMonitorReconciler) setup(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		Named("metrics").
		WithOptions(ctrlcontroller.Options{MaxConcurrentReconciles: 1}).
		For(&apiextensionsv1.CustomResourceDefinition{}).
		Watches(&corev1.Secret{}, toCRD, builder.WithPredicates(r.named(r.opts.token()))).
		Watches(&corev1.ConfigMap{}, toCRD, builder.WithPredicates(r.named(r.opts.ca())))
	if r.cert != nil {
		b = b.WatchesRawSource(source.Channel(r.cert.loaded, toCRD))
	}
	c, err := b.Build(r)
	r.ctrl = c
	return err
}

func newServiceMonitor() *unstructured.Unstructured {
	sm := &unstructured.Unstructured{}
	sm.SetGroupVersionKind(serviceMonitorGVK)
	return sm
}

// watchServiceMonitor starts watching the ServiceMonitor, which can only
// happen once its CRD is served, through a cache of the operator's
// namespace added to the running manager. It returns once the watch has
// synced, so the ServiceMonitor ensure creates is never missed.
func (r *serviceMonitorReconciler) watchServiceMonitor(ctx context.Context) error {
	if r.watching {
		return nil
	}
	if r.smCache == nil {
		c, err := cache.New(r.mgr.GetConfig(), cache.Options{
			Scheme:            r.mgr.GetScheme(),
			Mapper:            r.mgr.GetRESTMapper(),
			DefaultNamespaces: map[string]cache.Config{r.namespace: {}},
		})
		if err != nil {
			return err
		}
		if err := r.mgr.Add(c); err != nil {
			return err
		}
		r.smCache = c
	}
	if _, err := r.smCache.GetInformer(ctx, newServiceMonitor()); err != nil {
		return err
	}
	// An earlier watch's handler stayed on the informer removed with the
	// API, so each start adds a watch on the new one.
	src := source.Kind(r.smCache, client.Object(newServiceMonitor()), toCRD, r.named(r.opts.Service))
	if err := r.ctrl.Watch(src); err != nil {
		return err
	}
	// The source looks its informer up in the background; one it looked up
	// after unwatchServiceMonitor would list a resource no longer served.
	if err := src.WaitForSync(ctx); err != nil {
		return err
	}
	r.watching = true
	return nil
}

// unwatchServiceMonitor stops the ServiceMonitor informer once the API is
// going, and deletes the scraper's credentials, which nothing uses then.
func (r *serviceMonitorReconciler) unwatchServiceMonitor(ctx context.Context) error {
	if r.watching {
		if err := r.smCache.RemoveInformer(ctx, newServiceMonitor()); err != nil {
			return err
		}
		r.watching = false
		logf.FromContext(ctx).Info("ServiceMonitor API removed; stopped watching ServiceMonitors")
	}
	for _, obj := range []client.Object{
		&corev1.Secret{Namespace: r.namespace, Name: r.opts.token()},
		&corev1.ConfigMap{Namespace: r.namespace, Name: r.opts.ca()},
	} {
		if err := r.client.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

func (r *serviceMonitorReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var crd apiextensionsv1.CustomResourceDefinition
	err := r.client.Get(ctx, req.NamespacedName, &crd)
	if client.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, err
	}
	if err != nil || !crd.DeletionTimestamp.IsZero() || !established(&crd) {
		return reconcile.Result{}, r.unwatchServiceMonitor(ctx)
	}
	if err := r.watchServiceMonitor(ctx); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, r.ensure(ctx)
}

func established(crd *apiextensionsv1.CustomResourceDefinition) bool {
	for _, c := range crd.Status.Conditions {
		if c.Type == apiextensionsv1.Established {
			return c.Status == apiextensionsv1.ConditionTrue
		}
	}
	return false
}

func (r *serviceMonitorReconciler) ensure(ctx context.Context) error {
	var svc corev1.Service
	if err := r.reader.Get(ctx, types.NamespacedName{Namespace: r.namespace, Name: r.opts.Service}, &svc); err != nil {
		return err
	}
	owner := metav1ac.OwnerReference().
		WithAPIVersion("v1").WithKind("Service").WithName(svc.Name).WithUID(svc.UID)
	// The label puts the token Secret in the operator's Secret cache.
	labels := map[string]string{controller.LabelManagedBy: controller.ManagedBy}
	apply := func(obj runtime.ApplyConfiguration) error {
		return r.client.Apply(ctx, obj, client.FieldOwner(controller.FieldOwner), client.ForceOwnership)
	}

	endpoint := map[string]any{"port": metricsPort(&svc), "path": "/metrics", "scheme": "http"}
	if r.opts.Secure {
		if r.opts.Scraper == "" {
			return errors.New("no scraper ServiceAccount for the token")
		}
		if err := apply(corev1ac.Secret(r.opts.token(), r.namespace).
			WithType(corev1.SecretTypeServiceAccountToken).
			WithLabels(labels).
			WithAnnotations(map[string]string{corev1.ServiceAccountNameKey: r.opts.Scraper}).
			WithOwnerReferences(owner)); err != nil {
			return err
		}
		tlsConfig := map[string]any{"insecureSkipVerify": true}
		if r.cert.serving() {
			if err := apply(corev1ac.ConfigMap(r.opts.ca(), r.namespace).
				WithLabels(labels).
				WithAnnotations(map[string]string{injectCABundleAnnotation: "true"}).
				WithOwnerReferences(owner)); err != nil {
				return err
			}
			tlsConfig = map[string]any{
				"serverName": svc.Name + "." + r.namespace + ".svc",
				"ca":         map[string]any{"configMap": map[string]any{"name": r.opts.ca(), "key": serviceCAKey}},
			}
		}
		endpoint["scheme"] = "https"
		endpoint["tlsConfig"] = tlsConfig
		endpoint["authorization"] = map[string]any{
			"type":        "Bearer",
			"credentials": map[string]any{"name": r.opts.token(), "key": "token"},
		}
	}

	selector := map[string]any{}
	for k, v := range svc.Labels {
		selector[k] = v
	}
	sm := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"selector":  map[string]any{"matchLabels": selector},
			"endpoints": []any{endpoint},
		},
	}}
	sm.SetGroupVersionKind(serviceMonitorGVK)
	sm.SetNamespace(r.namespace)
	sm.SetName(svc.Name)
	sm.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}})
	return apply(client.ApplyConfigurationFromUnstructured(sm))
}

// metricsPort is the name of the Service's only port, or "https".
func metricsPort(svc *corev1.Service) string {
	if len(svc.Spec.Ports) == 1 && svc.Spec.Ports[0].Name != "" {
		return svc.Spec.Ports[0].Name
	}
	return "https"
}

// metricsCert is the metrics endpoint's certificate: a self-signed one
// until the service-ca certificate is mounted, then that one, followed
// through rotation. The kubelet fills the mounted directory once the Secret
// exists, which can be after the operator starts.
type metricsCert struct {
	certFile, keyFile string
	selfSigned        *tls.Certificate
	watcher           atomic.Pointer[certwatcher.CertWatcher]
	// loaded receives an event when the mounted certificate is first
	// served, so the ServiceMonitor can verify it.
	loaded chan event.GenericEvent
}

func newMetricsCert(certFile, keyFile string) (*metricsCert, error) {
	cert, key, err := certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", []net.IP{{127, 0, 0, 1}}, nil, "")
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	c := &metricsCert{certFile: certFile, keyFile: keyFile, selfSigned: &pair, loaded: make(chan event.GenericEvent, 1)}
	// A certificate mounted before start is served from the first handshake.
	if w, err := certwatcher.New(certFile, keyFile); err == nil {
		c.watcher.Store(w)
	}
	return c, nil
}

// GetCertificate is the metrics server's tls.Config.GetCertificate.
func (c *metricsCert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if w := c.watcher.Load(); w != nil {
		return w.GetCertificate(hello)
	}
	return c.selfSigned, nil
}

// serving reports whether the mounted certificate is served.
func (c *metricsCert) serving() bool { return c != nil && c.watcher.Load() != nil }

func (c *metricsCert) NeedLeaderElection() bool { return false }

// Start never fails the manager: metrics are served, with the certificate
// last read, whatever happens to the files.
func (c *metricsCert) Start(ctx context.Context) error {
	log := logf.FromContext(ctx)
	w := c.watcher.Load()
	if w == nil {
		if w = c.waitForFiles(ctx); w == nil {
			return nil
		}
		c.watcher.Store(w)
		log.Info("Serving the mounted metrics certificate", "cert", c.certFile)
		c.loaded <- event.GenericEvent{Object: &apiextensionsv1.CustomResourceDefinition{}}
	}
	if err := w.Start(ctx); err != nil {
		log.Error(err, "Not following metrics certificate changes")
		<-ctx.Done()
	}
	return nil
}

// waitForFiles returns a watcher of the mounted certificate once both files
// load, or nil when ctx ends first.
func (c *metricsCert) waitForFiles(ctx context.Context) *certwatcher.CertWatcher {
	log := logf.FromContext(ctx)
	var events <-chan fsnotify.Event
	var errs <-chan error
	if fw, err := fsnotify.NewWatcher(); err != nil {
		log.Info("Polling for the metrics certificate", "reason", err.Error())
	} else {
		defer func() { _ = fw.Close() }()
		if err := fw.Add(filepath.Dir(c.certFile)); err != nil {
			log.Info("Polling for the metrics certificate", "reason", err.Error())
		}
		events, errs = fw.Events, fw.Errors
	}
	// The poll covers a missing directory and events missed between reads.
	poll := time.NewTicker(10 * time.Second)
	defer poll.Stop()
	for {
		// Read after the watch starts, so files written in between are seen.
		if w, err := certwatcher.New(c.certFile, c.keyFile); err == nil {
			return w
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			log.Info("Metrics certificate watch error", "error", err.Error())
		case <-events:
		case <-poll.C:
		}
	}
}
