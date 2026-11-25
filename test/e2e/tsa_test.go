//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/sigstore/timestamp-authority/v2/pkg/verification"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
)

// TestOperatorRunsAsNamespaceUID checks that OLM's operator pod got the UID
// the restricted policy assigned to its namespace and runs the published
// image.
func TestOperatorRunsAsNamespaceUID(t *testing.T) {
	ctx := t.Context()
	uid, err := sccUID(ctx, operatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	pods := runningPods(t, ctx, operatorNamespace, operatorPods)
	for _, p := range pods {
		assertUID(t, p, uid)
		if img := p.Spec.Containers[0].Image; img != published.OperatorImage {
			t.Errorf("pod %s runs %s, not %s", p.Name, img, published.OperatorImage)
		}
	}
}

// TestMetricsScraper checks that OLM created the account Prometheus scrapes
// with, allowed /metrics and nothing else, and that the operator creates a
// ServiceMonitor for it only where the Prometheus Operator's API is served.
func TestMetricsScraper(t *testing.T) {
	ctx := t.Context()
	account := client.ObjectKey{Namespace: operatorNamespace, Name: metricsScraper}
	if err := k8s.Get(ctx, account, &corev1.ServiceAccount{}); err != nil {
		t.Fatal(err)
	}
	user := "system:serviceaccount:" + operatorNamespace + ":" + metricsScraper
	for _, tc := range []struct {
		name  string
		spec  authorizationv1.SubjectAccessReviewSpec
		allow bool
	}{
		{"read /metrics", authorizationv1.SubjectAccessReviewSpec{
			NonResourceAttributes: &authorizationv1.NonResourceAttributes{Path: "/metrics", Verb: "get"},
		}, true},
		{"read Secrets", authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: operatorNamespace, Resource: "secrets", Verb: "get",
			},
		}, false},
	} {
		tc.spec.User = user
		sar := &authorizationv1.SubjectAccessReview{Spec: tc.spec}
		if err := k8s.Create(ctx, sar); err != nil {
			t.Fatal(err)
		}
		if sar.Status.Allowed != tc.allow {
			t.Errorf("%s: allowed %v", tc.name, sar.Status.Allowed)
		}
	}

	monitors := &unstructured.UnstructuredList{}
	monitors.SetAPIVersion("monitoring.coreos.com/v1")
	monitors.SetKind("ServiceMonitorList")
	err := k8s.List(ctx, monitors, client.InNamespace(operatorNamespace))
	if meta.IsNoMatchError(err) {
		token := client.ObjectKey{Namespace: operatorNamespace, Name: metricsScraper + "-token"}
		if err := k8s.Get(ctx, token, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Errorf("token Secret without the ServiceMonitor API: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	sm := &unstructured.Unstructured{}
	sm.SetAPIVersion("monitoring.coreos.com/v1")
	sm.SetKind("ServiceMonitor")
	key := client.ObjectKey{Namespace: operatorNamespace, Name: "rhtas-pqc-controller-manager-metrics-service"}
	if err := poll(ctx, 2*time.Minute, func() (bool, error) {
		err := k8s.Get(ctx, key, sm)
		return err == nil, client.IgnoreNotFound(err)
	}); err != nil {
		t.Fatalf("ServiceMonitor %s: %v", key.Name, err)
	}
}

// TestTimestamp creates an instance in the SCC namespace, asks its TSA for a
// timestamp through the Service and verifies the response against the
// instance's published trust anchor.
func TestTimestamp(t *testing.T) {
	ctx := t.Context()
	const algorithm = pqcv1alpha1.MLDSA87
	cr := &pqcv1alpha1.SecureSignPQC{
		Namespace: namespace, Name: "e2e",
		Spec: pqcv1alpha1.SecureSignPQCSpec{Version: "2.0", TSA: pqcv1alpha1.TSASpec{
			Signing: pqcv1alpha1.SigningSpec{Algorithm: algorithm},
			// MicroShift has no cluster ingress domain to default the host from.
			Ingress: pqcv1alpha1.IngressSpec{Enabled: true, Host: "e2e-tsa." + namespace + ".example.test"},
		}},
	}
	deleteInstance(t, cr)
	created := time.Now()
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteInstance(t, cr) })

	if err := waitReady(ctx, cr); err != nil {
		t.Fatalf("instance not Ready: %v; conditions %+v", err, cr.Status.Conditions)
	}
	t.Logf("instance Ready %s after creation", time.Since(created).Round(time.Second))
	checkIngress(t, ctx, cr)

	uid, err := sccUID(ctx, namespace)
	if err != nil {
		t.Fatal(err)
	}
	var d appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: controller.TSAName(cr.Name)}, &d); err != nil {
		t.Fatal(err)
	}
	for _, p := range runningPods(t, ctx, namespace, d.Spec.Selector.MatchLabels) {
		assertUID(t, p, uid)
	}

	s, err := stamp(ctx, cr)
	if err != nil {
		logPods(t, ctx, namespace, d.Spec.Selector.MatchLabels)
		t.Fatal(err)
	}
	ts, intermediate, err := verifyTrusted(ctx, cr, s)
	if err != nil {
		t.Fatalf("verify against the instance's trusted root: %v", err)
	}
	// The signing certificate is the active signer's, with the instance's
	// algorithm.
	leaf, err := signingCert(ts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pki.AlgorithmOf(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != algorithm {
		t.Errorf("timestamp signed with %s, instance asks for %s", got, algorithm)
	}
	var active []string
	for _, s := range cr.Status.TSA.Signers {
		if s.Stage == pqcv1alpha1.KeyActive {
			active = append(active, s.SerialNumber)
		}
	}
	if serial := leaf.SerialNumber.Text(16); len(active) != 1 || active[0] != serial {
		t.Errorf("timestamp signed by serial %s, active signers %v", serial, active)
	}
	if age := time.Since(ts.Time); age < -time.Minute || age > 5*time.Minute {
		t.Errorf("timestamp time %s is %s from now", ts.Time, age)
	}

	// The same response does not verify against another trust anchor.
	foreign, err := pki.NewRoot(algorithm, "foreign", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verification.VerifyTimestampResponse(s.tsr, bytes.NewReader(s.artifact), verification.VerifyOpts{
		Roots: []*x509.Certificate{foreign.Cert}, Intermediates: []*x509.Certificate{intermediate}, Nonce: s.nonce,
	}); err == nil {
		t.Error("response verified against a foreign root")
	}
}

// TestCARotation rotates an instance's intermediate and then its root,
// timestamping during each rollout. Timestamps from before and after each
// rotation verify against the trusted root, new ones chain to the new
// CA, and the old CA keys are deleted.
func TestCARotation(t *testing.T) {
	ctx := t.Context()
	cr := &pqcv1alpha1.SecureSignPQC{
		Namespace: namespace, Name: "e2e-rotate",
		Spec: pqcv1alpha1.SecureSignPQCSpec{Version: "2.0"},
	}
	deleteInstance(t, cr)
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteInstance(t, cr) })
	if err := waitRotated(ctx, cr, nil, "Root 1-0 Active", "Intermediate 1-1 Active"); err != nil {
		t.Fatal(err)
	}
	stamps := []*stamped{}
	take := func() *stamped {
		t.Helper()
		s, err := stamp(ctx, cr)
		if err != nil {
			t.Fatal(err)
		}
		stamps = append(stamps, s)
		return s
	}
	issuer := func(s *stamped) *x509.Certificate {
		t.Helper()
		_, intermediate, err := verifyTrusted(ctx, cr, s)
		if err != nil {
			t.Fatal(err)
		}
		return intermediate
	}
	first := issuer(take())

	edit := func(f func(*pqcv1alpha1.SigningSpec)) {
		t.Helper()
		if err := editSigning(ctx, cr, f); err != nil {
			t.Fatal(err)
		}
	}
	// Timestamps issued while the pods move must verify too, the old
	// pods' included.
	during := func() error {
		s, err := stamp(ctx, cr)
		if err == nil {
			stamps = append(stamps, s)
		}
		return err
	}

	edit(func(s *pqcv1alpha1.SigningSpec) { s.IntermediateGeneration = 2 })
	if err := waitRotated(ctx, cr, during,
		"Root 1-0 Active", "Intermediate 1-2 Active", "Intermediate 1-1 Retired"); err != nil {
		t.Fatal(err)
	}
	second := issuer(take())
	if second.Equal(first) || !bytes.Equal(second.RawIssuer, first.RawIssuer) {
		t.Fatalf("after the intermediate rotation timestamps chain to %s under %s", second.Subject, second.Issuer)
	}

	edit(func(s *pqcv1alpha1.SigningSpec) { s.RootGeneration = 2 })
	if err := waitRotated(ctx, cr, during,
		"Root 2-0 Active", "Intermediate 2-2 Active",
		"Root 1-0 Retired", "Intermediate 1-2 Retired", "Intermediate 1-1 Retired"); err != nil {
		t.Fatal(err)
	}
	third := issuer(take())
	if bytes.Equal(third.RawIssuer, first.RawIssuer) {
		t.Fatal("after the root rotation timestamps still chain to the old root")
	}
	for i, s := range stamps {
		if _, _, err := verifyTrusted(ctx, cr, s); err != nil {
			t.Errorf("timestamp %d: %v", i, err)
		}
	}
	keys, err := keySecrets(ctx, client.ObjectKeyFromObject(cr))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		controller.TSAIntermediateSecretName(cr.Name, 2, 2),
		controller.TSARootSecretName(cr.Name, 2),
		controller.TSASignerSecretName(cr.Name, 2, 2, 1),
	}
	if got := slices.Sorted(maps.Keys(keys)); !slices.Equal(got, want) {
		t.Fatalf("key Secrets %v, want %v", got, want)
	}
}

// editSigning changes cr's spec.tsa.signing, retrying on a conflict with
// the operator's status writes.
func editSigning(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, f func(*pqcv1alpha1.SigningSpec)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(cr), cr); err != nil {
			return err
		}
		f(&cr.Spec.TSA.Signing)
		return k8s.Update(ctx, cr)
	})
}

// waitRotated waits until cr has rolled out its spec with no CA rotation
// in progress and status.tsa.cas reads want, calling during, if set, on
// each poll and failing on its first error.
func waitRotated(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, during func() error, want ...string) error {
	return waitSettled(ctx, cr, during, func(got []string) bool { return slices.Equal(got, want) })
}

// waitSettled waits until cr has rolled out its spec with no CA rotation
// in progress and match accepts its caStages, calling during as
// waitRotated does.
func waitSettled(
	ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, during func() error, match func([]string) bool,
) error {
	var last string
	err := poll(ctx, 5*time.Minute, func() (bool, error) {
		if during != nil {
			if err := during(); err != nil {
				return false, fmt.Errorf("during the rollout: %w", err)
			}
		}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(cr), cr); err != nil {
			return false, err
		}
		got := caStages(cr)
		last = fmt.Sprintf("cas %v, conditions %+v", got, cr.Status.Conditions)
		return cr.Status.ObservedGeneration == cr.Generation &&
			meta.IsStatusConditionTrue(cr.Status.Conditions, pqcv1alpha1.ConditionReady) &&
			meta.IsStatusConditionFalse(cr.Status.Conditions, pqcv1alpha1.ConditionTSACARotation) &&
			match(got), nil
	})
	if err != nil {
		return fmt.Errorf("%w; last %s", err, last)
	}
	return nil
}

// checkIngress checks the TSA Ingress and, on OpenShift, that the router
// admitted the Route made from it with edge TLS.
func checkIngress(t *testing.T, ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) {
	t.Helper()
	host := cr.Spec.TSA.Ingress.Host
	scheme := "http"
	if openshift {
		scheme = "https"
	}
	if !meta.IsStatusConditionTrue(cr.Status.Conditions, pqcv1alpha1.ConditionTSAIngressReady) {
		c := meta.FindStatusCondition(cr.Status.Conditions, pqcv1alpha1.ConditionTSAIngressReady)
		t.Errorf("TSAIngressReady not True: %+v", c)
	}
	if got := cr.Status.TSA.ExternalURL; got != scheme+"://"+host {
		t.Errorf("status.tsa.externalURL %q, want %s://%s", got, scheme, host)
	}
	var ing networkingv1.Ingress
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: controller.TSAName(cr.Name)}, &ing); err != nil {
		t.Fatal(err)
	}
	if len(ing.Spec.Rules) != 1 || ing.Spec.Rules[0].Host != host {
		t.Fatalf("Ingress rules %+v", ing.Spec.Rules)
	}
	if !openshift {
		return
	}
	var termination string
	if err := poll(ctx, 2*time.Minute, func() (bool, error) {
		var routes unstructured.UnstructuredList
		routes.SetAPIVersion("route.openshift.io/v1")
		routes.SetKind("RouteList")
		if err := k8s.List(ctx, &routes, client.InNamespace(namespace)); err != nil {
			return false, err
		}
		for _, r := range routes.Items {
			if !metav1.IsControlledBy(&r, &ing) {
				continue
			}
			termination, _, _ = unstructured.NestedString(r.Object, "spec", "tls", "termination")
			ingresses, _, _ := unstructured.NestedSlice(r.Object, "status", "ingress")
			for _, i := range ingresses {
				conds, _, _ := unstructured.NestedSlice(i.(map[string]any), "conditions")
				for _, c := range conds {
					c := c.(map[string]any)
					if c["type"] == "Admitted" && c["status"] == "True" {
						return true, nil
					}
				}
			}
		}
		return false, nil
	}); err != nil {
		t.Fatalf("no admitted Route for Ingress %s: %v", ing.Name, err)
	}
	if termination != "edge" {
		t.Errorf("Route TLS termination %q, want edge", termination)
	}
}

// requestTimestamp posts an RFC 3161 request to the TSA Service through the
// API server's service proxy.
func requestTimestamp(ctx context.Context, ns, service string, req []byte) ([]byte, error) {
	res := clientset.CoreV1().RESTClient().Post().
		Namespace(ns).Resource("services").Name(fmt.Sprintf("%s:%d", service, 3000)).
		SubResource("proxy").Suffix("api/v1/timestamp").
		SetHeader("Content-Type", "application/timestamp-query").
		SetHeader("Accept", "application/timestamp-reply").
		Body(req).Do(ctx)
	body, err := res.Raw()
	if err != nil {
		var code int
		res.StatusCode(&code)
		return nil, fmt.Errorf("timestamp request: HTTP %d: %w: %s", code, err, body)
	}
	var ct string
	res.ContentType(&ct)
	if ct != "application/timestamp-reply" {
		return nil, fmt.Errorf("timestamp response has content type %q", ct)
	}
	return body, nil
}

func deleteInstance(t *testing.T, cr *pqcv1alpha1.SecureSignPQC) {
	t.Helper()
	ctx := context.Background()
	if err := k8s.Delete(ctx, cr.DeepCopy()); client.IgnoreNotFound(err) != nil {
		t.Fatal(err)
	}
	if err := poll(ctx, 2*time.Minute, func() (bool, error) {
		err := k8s.Get(ctx, client.ObjectKeyFromObject(cr), &pqcv1alpha1.SecureSignPQC{})
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	}); err != nil {
		t.Fatalf("instance %s not deleted: %v", cr.Name, err)
	}
	// Keys and chain records outlive their instance on purpose; a test
	// that recreates the instance starts from none.
	for _, obj := range []client.Object{&corev1.Secret{}, &corev1.ConfigMap{}} {
		if err := k8s.DeleteAllOf(ctx, obj, client.InNamespace(cr.Namespace),
			client.MatchingLabels{controller.LabelInstance: cr.Name, controller.LabelManagedBy: controller.ManagedBy},
			client.HasLabels{controller.LabelKeyRole}); err != nil {
			t.Fatal(err)
		}
	}
}

// runningPods waits for the pods matching labels in ns to be running and
// ready, and returns them.
func runningPods(t *testing.T, ctx context.Context, ns string, labels map[string]string) []corev1.Pod {
	t.Helper()
	var pods corev1.PodList
	if err := poll(ctx, 3*time.Minute, func() (bool, error) {
		if err := k8s.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
			return false, err
		}
		if len(pods.Items) == 0 {
			return false, nil
		}
		for _, p := range pods.Items {
			if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
				return false, nil
			}
			for _, c := range p.Status.ContainerStatuses {
				if !c.Ready {
					return false, nil
				}
			}
		}
		return true, nil
	}); err != nil {
		t.Fatalf("pods %v in %s not ready: %v", labels, ns, err)
	}
	return pods.Items
}

// logPods logs the tail of each matching pod's log, for a failed request.
func logPods(t *testing.T, ctx context.Context, ns string, labels map[string]string) {
	t.Helper()
	var pods corev1.PodList
	if err := k8s.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		t.Log(err)
		return
	}
	tail := int64(80)
	for _, p := range pods.Items {
		out, err := clientset.CoreV1().Pods(ns).GetLogs(p.Name, &corev1.PodLogOptions{TailLines: &tail}).DoRaw(ctx)
		t.Logf("pod %s log (%v):\n%s", p.Name, err, out)
	}
}

// assertUID checks that every container of p runs as uid, whether the UID
// was set on the pod (kind's policy) or on each container (SCC admission),
// and on OpenShift that p was admitted under restricted-v2.
func assertUID(t *testing.T, p corev1.Pod, uid int64) {
	t.Helper()
	var podUID *int64
	if p.Spec.SecurityContext != nil {
		podUID = p.Spec.SecurityContext.RunAsUser
	}
	for _, c := range p.Spec.Containers {
		got := podUID
		if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
			got = c.SecurityContext.RunAsUser
		}
		switch {
		case got == nil:
			t.Errorf("pod %s/%s container %s has no runAsUser, namespace UID %d", p.Namespace, p.Name, c.Name, uid)
		case *got != uid:
			t.Errorf("pod %s/%s container %s runAsUser %d, namespace UID %d", p.Namespace, p.Name, c.Name, *got, uid)
		}
	}
	if scc := p.Annotations["openshift.io/scc"]; openshift && scc != sccRestricted {
		t.Errorf("pod %s/%s admitted under SCC %q, not %s", p.Namespace, p.Name, scc, sccRestricted)
	}
}
