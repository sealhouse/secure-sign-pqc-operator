package operator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
)

// stubServiceMonitorCRD stands in for the Prometheus Operator's API. It and
// getServiceMonitor spell that API out rather than use the operator's
// constants, so a wrong group, version or kind there fails these tests.
func stubServiceMonitorCRD() *apiextensionsv1.CustomResourceDefinition {
	return stubCRD("monitoring.coreos.com", "servicemonitors", "ServiceMonitor", apiextensionsv1.NamespaceScoped)
}

func getServiceMonitor(ctx context.Context, ns string) (*unstructured.Unstructured, error) {
	sm := &unstructured.Unstructured{}
	sm.SetAPIVersion("monitoring.coreos.com/v1")
	sm.SetKind("ServiceMonitor")
	err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: "metrics"}, sm)
	return sm, err
}

func endpointOf(sm *unstructured.Unstructured) map[string]any {
	eps, _, _ := unstructured.NestedSlice(sm.Object, "spec", "endpoints")
	if len(eps) != 1 {
		return nil
	}
	ep, _ := eps[0].(map[string]any)
	return ep
}

// deleteAndWaitRecreated deletes obj and waits for the operator to put it
// back, as a new object.
func deleteAndWaitRecreated(t *testing.T, obj client.Object) {
	t.Helper()
	ctx := context.Background()
	if err := k8s.Delete(ctx, obj); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, obj.GetName()+" recreated", func() error {
		got := obj.DeepCopyObject().(client.Object)
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), got); err != nil {
			return err
		}
		if got.GetUID() == obj.GetUID() {
			return errors.New("not yet deleted")
		}
		return nil
	})
}

// endpointIs gets the ServiceMonitor and checks its one endpoint.
func endpointIs(ctx context.Context, ns string, check func(map[string]any) error) func() error {
	return func() error {
		sm, err := getServiceMonitor(ctx, ns)
		if err != nil {
			return err
		}
		return check(endpointOf(sm))
	}
}

// The operator, holding only the RBAC it ships with, creates a
// ServiceMonitor when the API is installed, and puts back what is deleted:
// verifying a service-ca certificate, or skipping verification of a
// self-signed one.
func TestServiceMonitor(t *testing.T) {
	ctx := context.Background()
	opns := createNamespace(t, "op")
	userCfg, _ := operatorUser(t, opns)
	svc := &corev1.Service{
		Namespace: opns, Name: "metrics", Labels: map[string]string{
			controller.LabelName: "secure-sign-pqc-operator", controller.LabelComponent: "metrics",
		},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "https", Port: 8443}}},
	}
	if err := k8s.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	metricsOpts := MetricsOptions{Service: "metrics", Scraper: "scraper", Secure: true}
	start := func(t *testing.T, edit func(*MetricsOptions)) {
		t.Helper()
		o := metricsOpts
		if edit != nil {
			edit(&o)
		}
		startOperatorWith(t, userCfg, opns, func(op *Options) { op.Metrics = o })
	}

	parent := t
	t.Run("self-signed", func(t *testing.T) {
		start(t, nil)
		time.Sleep(time.Second)
		token := client.ObjectKey{Namespace: opns, Name: metricsOpts.token()}
		if err := k8s.Get(ctx, token, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("token Secret without the ServiceMonitor API: %v", err)
		}
		// The later subtests use the API too.
		installCRDs(t, parent, stubServiceMonitorCRD())
		eventually(t, 30*time.Second, "ServiceMonitor", endpointIs(ctx, opns, func(ep map[string]any) error {
			insecure, _, _ := unstructured.NestedBool(ep, "tlsConfig", "insecureSkipVerify")
			token, _, _ := unstructured.NestedString(ep, "authorization", "credentials", "name")
			if ep["scheme"] != "https" || ep["port"] != "https" || !insecure || token != metricsOpts.token() {
				return fmt.Errorf("endpoint %v", ep)
			}
			return nil
		}))
		first, err := getServiceMonitor(ctx, opns)
		if err != nil {
			t.Fatal(err)
		}
		selector, _, _ := unstructured.NestedStringMap(first.Object, "spec", "selector", "matchLabels")
		if !maps.Equal(selector, svc.Labels) {
			t.Errorf("selector %v, want %v", selector, svc.Labels)
		}
		var secret corev1.Secret
		if err := k8s.Get(ctx, token, &secret); err != nil {
			t.Fatal(err)
		}
		if secret.Type != corev1.SecretTypeServiceAccountToken || secret.Annotations[corev1.ServiceAccountNameKey] != "scraper" {
			t.Errorf("token Secret type %s, annotations %v", secret.Type, secret.Annotations)
		}
		var live corev1.Service
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(svc), &live); err != nil {
			t.Fatal(err)
		}
		for _, obj := range []metav1.Object{first, &secret} {
			if refs := obj.GetOwnerReferences(); len(refs) != 1 || refs[0].UID != live.UID {
				t.Errorf("%s owners %v, want the Service", obj.GetName(), refs)
			}
		}

		deleteAndWaitRecreated(t, first)
		deleteAndWaitRecreated(t, &secret)
	})

	t.Run("service-ca certificate mounted after start", func(t *testing.T) {
		dir := t.TempDir()
		start(t, func(o *MetricsOptions) {
			o.CertFile, o.KeyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
		})
		eventually(t, 30*time.Second, "ServiceMonitor skipping verification", endpointIs(ctx, opns, func(ep map[string]any) error {
			if insecure, _, _ := unstructured.NestedBool(ep, "tlsConfig", "insecureSkipVerify"); !insecure {
				return fmt.Errorf("endpoint %v", ep)
			}
			return nil
		}))
		writeServingCert(t, dir, "metrics")
		eventually(t, 30*time.Second, "verifying ServiceMonitor", endpointIs(ctx, opns, func(ep map[string]any) error {
			tlsConfig, _, _ := unstructured.NestedMap(ep, "tlsConfig")
			ca, _, _ := unstructured.NestedStringMap(tlsConfig, "ca", "configMap")
			if _, insecure := tlsConfig["insecureSkipVerify"]; insecure ||
				tlsConfig["serverName"] != "metrics."+opns+".svc" ||
				!maps.Equal(ca, map[string]string{"name": metricsOpts.ca(), "key": "service-ca.crt"}) {
				return fmt.Errorf("tlsConfig %v", tlsConfig)
			}
			return nil
		}))
		var ca corev1.ConfigMap
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: opns, Name: metricsOpts.ca()}, &ca); err != nil {
			t.Fatal(err)
		}
		if ca.Annotations[injectCABundleAnnotation] != "true" {
			t.Errorf("CA ConfigMap annotations %v", ca.Annotations)
		}
	})

	t.Run("plain HTTP", func(t *testing.T) {
		start(t, func(o *MetricsOptions) { o.Secure = false })
		eventually(t, 30*time.Second, "HTTP ServiceMonitor", endpointIs(ctx, opns, func(ep map[string]any) error {
			_, tls := ep["tlsConfig"]
			_, auth := ep["authorization"]
			if ep["scheme"] != "http" || tls || auth {
				return fmt.Errorf("endpoint %v", ep)
			}
			return nil
		}))
	})

	t.Run("API removed and reinstalled", func(t *testing.T) { serviceMonitorRemoved(t, userCfg, opns, metricsOpts) })
}

// serviceMonitorRemoved checks that removing the ServiceMonitor API stops
// the watch and deletes the scraper's credentials, and that reinstalling it
// brings the ServiceMonitor back, watched again.
func serviceMonitorRemoved(t *testing.T, userCfg *rest.Config, opns string, metricsOpts MetricsOptions) {
	ctx := context.Background()
	var tracker serviceMonitorRequests
	tracked := rest.CopyConfig(userCfg)
	tracked.Wrap(tracker.wrap)
	dir := t.TempDir()
	writeServingCert(t, dir, "metrics")
	o := metricsOpts
	o.CertFile, o.KeyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	startOperatorWith(t, tracked, opns, func(op *Options) { op.Metrics = o })
	eventually(t, 30*time.Second, "ServiceMonitor", endpointIs(ctx, opns, func(map[string]any) error { return nil }))
	eventually(t, 10*time.Second, "ServiceMonitor watch", func() error {
		if n := tracker.watches.Load(); n != 1 {
			return fmt.Errorf("%d watches open", n)
		}
		return nil
	})
	credentials := []client.Object{
		&corev1.Secret{Namespace: opns, Name: metricsOpts.token()},
		&corev1.ConfigMap{Namespace: opns, Name: metricsOpts.ca()},
	}
	for _, obj := range credentials {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			t.Fatal(err)
		}
	}
	crds := []*apiextensionsv1.CustomResourceDefinition{stubServiceMonitorCRD()}
	// An informer left running would keep retrying the removed resource.
	if err := envtest.UninstallCRDs(cfg, envtest.CRDInstallOptions{CRDs: crds}); err != nil {
		t.Fatal(err)
	}
	for _, obj := range credentials {
		eventually(t, 30*time.Second, obj.GetName()+" deleted", gone(obj))
	}
	eventually(t, 10*time.Second, "ServiceMonitor watch closed", func() error {
		if n := tracker.watches.Load(); n != 0 {
			return fmt.Errorf("%d watches open", n)
		}
		return nil
	})
	requests := tracker.requests.Load()
	time.Sleep(2 * time.Second)
	if n := tracker.requests.Load() - requests; n != 0 {
		t.Fatalf("%d ServiceMonitor requests after the API was removed", n)
	}

	if _, err := envtest.InstallCRDs(cfg, envtest.CRDInstallOptions{CRDs: crds}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "ServiceMonitor after reinstall", endpointIs(ctx, opns, func(map[string]any) error { return nil }))
	sm, err := getServiceMonitor(ctx, opns)
	if err != nil {
		t.Fatal(err)
	}
	deleteAndWaitRecreated(t, sm)
}

// serviceMonitorRequests counts a client's ServiceMonitor requests and the
// watches among them still open.
type serviceMonitorRequests struct {
	requests, watches atomic.Int32
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type closeFunc struct {
	io.ReadCloser
	once  sync.Once
	close func()
}

func (c *closeFunc) Close() error {
	c.once.Do(c.close)
	return c.ReadCloser.Close()
}

func (s *serviceMonitorRequests) wrap(rt http.RoundTripper) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.URL.Path, "/servicemonitors") {
			return rt.RoundTrip(req)
		}
		s.requests.Add(1)
		resp, err := rt.RoundTrip(req)
		if w := req.URL.Query().Get("watch"); err == nil && (w == "true" || w == "1") {
			s.watches.Add(1)
			resp.Body = &closeFunc{ReadCloser: resp.Body, close: func() { s.watches.Add(-1) }}
		}
		return resp, err
	})
}

// writeServingCert writes a certificate for host, and its key, as the
// kubelet mounts a service-ca Secret.
func writeServingCert(t *testing.T, dir, host string) {
	t.Helper()
	cert, key, err := certutil.GenerateSelfSignedCertKey(host, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), cert, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The metrics endpoint serves a self-signed certificate until the mounted
// one appears, then that one, through rotation.
func TestMetricsCertFollowsFiles(t *testing.T) {
	dir := t.TempDir()
	c, err := newMetricsCert(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	served := func() string {
		cert, err := c.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.Subject.CommonName
	}
	servedFor := func(host string) func() error {
		return func() error {
			if cn := served(); !strings.HasPrefix(cn, host+"@") {
				return fmt.Errorf("serving %s", cn)
			}
			return nil
		}
	}
	if err := servedFor("localhost")(); err != nil {
		t.Fatalf("before the files exist: %v, want the self-signed localhost", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Start(t.Context()) }()
	if c.serving() {
		t.Fatal("serving the mounted certificate before it exists")
	}

	writeServingCert(t, dir, "first")
	eventually(t, 15*time.Second, "mounted certificate served", servedFor("first"))
	select {
	case <-c.loaded:
	case <-time.After(5 * time.Second):
		t.Fatal("no event for the ServiceMonitor")
	}
	if !c.serving() {
		t.Fatal("serving() false with the mounted certificate served")
	}
	writeServingCert(t, dir, "rotated")
	eventually(t, 30*time.Second, "rotated certificate served", servedFor("rotated"))
	select {
	case err := <-done:
		t.Fatalf("Start returned %v while its context runs", err)
	default:
	}
}

// The metrics server presents the mounted certificate once it appears,
// without a restart.
func TestMetricsEndpointServesMountedCert(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	dir := t.TempDir()
	r := startOperator(t, createNamespace(t, "op"), func(o *Options) {
		o.Manager.Metrics = metricsserver.Options{BindAddress: addr, SecureServing: true}
		o.Metrics = MetricsOptions{Secure: true, CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key")}
	})
	presented := func(host string) func() error {
		return func() error {
			conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspects the served certificate
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; !strings.HasPrefix(cn, host+"@") {
				return fmt.Errorf("presented %s", cn)
			}
			return nil
		}
	}
	eventually(t, 30*time.Second, "self-signed certificate presented", presented("localhost"))
	writeServingCert(t, dir, "metrics")
	eventually(t, 30*time.Second, "mounted certificate presented", presented("metrics"))
	if n := r.restarts.Load(); n != 0 {
		t.Fatalf("%d restarts", n)
	}
}

// A certificate mounted before start is served at once.
func TestMetricsCertMountedBeforeStart(t *testing.T) {
	dir := t.TempDir()
	writeServingCert(t, dir, "mounted")
	c, err := newMetricsCert(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.serving() {
		t.Fatal("not serving the mounted certificate before Start")
	}
	cert, err := c.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if cn := leaf.Subject.CommonName; !strings.HasPrefix(cn, "mounted@") {
		t.Fatalf("serving %s", cn)
	}
}
