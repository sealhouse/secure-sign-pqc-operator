package operator

import (
	"context"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

// operatorManager is the operator's field manager. Renaming it orphans the
// fields earlier releases own.
const operatorManager = "rhtas-pqc-operator"

// reconcileOnce runs one reconcile pass through c, with no manager or cache.
func reconcileOnce(t *testing.T, c client.Client, ns string) {
	t.Helper()
	profiles, err := supported.Load()
	if err != nil {
		t.Fatal(err)
	}
	r := &controller.SecureSignPQCReconciler{Client: c, APIReader: k8s, Profiles: profiles, Settings: tuning.NewLive(testSettings())}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{Namespace: ns, Name: "demo"}); err != nil {
		t.Fatal(err)
	}
}

// reconcileReady installs the demo instance in ns and reconciles it to Ready.
func reconcileReady(t *testing.T, ns string) {
	t.Helper()
	if err := k8s.Create(context.Background(), newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	reconcileOnce(t, k8s, ns)
	markAvailable(t, ns)
	reconcileOnce(t, k8s, ns)
	if err := conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionTrue, ""); err != nil {
		t.Fatal(err)
	}
}

func tsaObjects(t *testing.T, ns string) (*appsv1.Deployment, *corev1.Service) {
	t.Helper()
	ctx := context.Background()
	key := client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}
	var d appsv1.Deployment
	if err := k8s.Get(ctx, key, &d); err != nil {
		t.Fatal(err)
	}
	var s corev1.Service
	if err := k8s.Get(ctx, key, &s); err != nil {
		t.Fatal(err)
	}
	return &d, &s
}

func TestRepeatedReconcileWritesNothing(t *testing.T) {
	ns := createNamespace(t, "noop")
	reconcileReady(t, ns)
	versions := func() []string {
		d, s := tsaObjects(t, ns)
		return []string{d.ResourceVersion, s.ResourceVersion, getCR(t, ns).ResourceVersion}
	}
	before := versions()
	reconcileOnce(t, k8s, ns)
	reconcileOnce(t, k8s, ns)
	if after := versions(); !slices.Equal(before, after) {
		t.Fatalf("resource versions moved from %v to %v", before, after)
	}
}

func TestStatusIsApplied(t *testing.T) {
	ns := createNamespace(t, "status")
	reconcileReady(t, ns)
	applied := false
	for _, m := range getCR(t, ns).ManagedFields {
		if m.Subresource != "status" {
			continue
		}
		if m.Manager != operatorManager || m.Operation != metav1.ManagedFieldsOperationApply {
			t.Errorf("status written by %s with %s", m.Manager, m.Operation)
			continue
		}
		applied = true
	}
	if !applied {
		t.Fatal("no applied status")
	}
}

func TestApplyOwnership(t *testing.T) {
	ctx := context.Background()
	ns := createNamespace(t, "ownership")
	reconcileReady(t, ns)
	d, s := tsaObjects(t, ns)

	// A field only an earlier release of the operator set.
	earlier, err := appsv1ac.ExtractDeployment(d, operatorManager)
	if err != nil {
		t.Fatal(err)
	}
	earlier.WithAnnotations(map[string]string{"example.com/earlier": "dropped"})
	if err := k8s.Apply(ctx, earlier, client.FieldOwner(operatorManager), client.ForceOwnership); err != nil {
		t.Fatal(err)
	}

	foreign := client.RawPatch(client.Merge.Type(), []byte(`{"metadata":{"annotations":{"example.com/foreign":"kept"}}}`))
	if err := k8s.Patch(ctx, d, foreign, client.FieldOwner("someone-else")); err != nil {
		t.Fatal(err)
	}
	if err := k8s.Patch(ctx, s, foreign, client.FieldOwner("someone-else")); err != nil {
		t.Fatal(err)
	}
	drift := client.RawPatch(client.Merge.Type(), []byte(`{"spec":{"replicas":5}}`))
	if err := k8s.Patch(ctx, d, drift, client.FieldOwner("someone-else")); err != nil {
		t.Fatal(err)
	}

	reconcileOnce(t, k8s, ns)
	d, s = tsaObjects(t, ns)
	if _, ok := d.Annotations["example.com/earlier"]; ok {
		t.Error("the field the operator stopped setting is still there")
	}
	if d.Annotations["example.com/foreign"] != "kept" || s.Annotations["example.com/foreign"] != "kept" {
		t.Errorf("foreign annotation lost: Deployment %v, Service %v", d.Annotations, s.Annotations)
	}
	if got := ptr.Deref(d.Spec.Replicas, 0); got != 1 {
		t.Errorf("replicas %d, want the operator's 1", got)
	}
}

// staleCR serves one old copy of the instance, as a lagging cache does.
type staleCR struct {
	client.Client
	cr *pqcv1alpha1.SecureSignPQC
}

func (s staleCR) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if cr, ok := obj.(*pqcv1alpha1.SecureSignPQC); ok {
		s.cr.DeepCopyInto(cr)
		return nil
	}
	return s.Client.Get(ctx, key, obj, opts...)
}

// A pass that follows a retirement must not lose the retired key's record,
// however far the cache lags.
func TestStaleCacheKeepsRetiredKey(t *testing.T) {
	ns := createNamespace(t, "stale")
	reconcileReady(t, ns)
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) {
		s.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA87
		s.TSA.Signing.SignerGeneration = 2
	})
	reconcileOnce(t, k8s, ns)
	stale := getCR(t, ns)
	const want = "2:ML-DSA-87:Active,1:ML-DSA-65:Retired"
	if got := signerStatus(stale); got != "2:ML-DSA-87:Pending,1:ML-DSA-65:Active" {
		t.Fatalf("signers %s before the rollout", got)
	}
	markAvailable(t, ns)
	reconcileOnce(t, k8s, ns)
	if got := signerStatus(getCR(t, ns)); got != want {
		t.Fatalf("signers %s after the rollout, want %s", got, want)
	}
	reconcileOnce(t, staleCR{Client: k8s, cr: stale}, ns)
	if got := signerStatus(getCR(t, ns)); got != want {
		t.Fatalf("signers %s after a pass on a stale read, want %s", got, want)
	}
}
