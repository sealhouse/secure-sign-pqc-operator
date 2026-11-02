package operator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

func newInstance(ns string) *pqcv1alpha1.SecureSignPQC {
	return &pqcv1alpha1.SecureSignPQC{
		Namespace: ns, Name: "demo",
		Spec: pqcv1alpha1.SecureSignPQCSpec{Version: "2.0"},
	}
}

func TestCRDDefaultsAndValidation(t *testing.T) {
	ctx := context.Background()
	ns := createNamespace(t, "crd")

	cr := newInstance(ns)
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	if cr.Spec.TSA.Signing.Algorithm != pqcv1alpha1.MLDSA65 {
		t.Errorf("default algorithm %q, want ML-DSA-65", cr.Spec.TSA.Signing.Algorithm)
	}
	if ptr.Deref(cr.Spec.TSA.Replicas, 0) != 1 {
		t.Errorf("default tsa.replicas %v, want 1", cr.Spec.TSA.Replicas)
	}
	if cr.Spec.TSA.Signing.SignerGeneration != 1 {
		t.Errorf("default tsa.signing.signerGeneration %d, want 1", cr.Spec.TSA.Signing.SignerGeneration)
	}

	cr.Spec.TSA.Signing.SignerGeneration = 3
	if err := k8s.Update(ctx, cr); err != nil {
		t.Errorf("raise signerGeneration: %v", err)
	}
	cr.Spec.TSA.Signing.SignerGeneration = 2
	if err := k8s.Update(ctx, cr); !apierrors.IsInvalid(err) {
		t.Errorf("lower signerGeneration: got %v, want Invalid", err)
	}

	for _, tc := range []struct {
		name string
		spec pqcv1alpha1.SecureSignPQCSpec
	}{
		{"unknown-version", pqcv1alpha1.SecureSignPQCSpec{Version: "1.0"}},
		{"unknown-algorithm", pqcv1alpha1.SecureSignPQCSpec{Version: "2.0", TSA: pqcv1alpha1.TSASpec{Signing: pqcv1alpha1.SigningSpec{Algorithm: "RSA"}}}},
		{"zero-replicas", pqcv1alpha1.SecureSignPQCSpec{Version: "2.0", TSA: pqcv1alpha1.TSASpec{Replicas: ptr.To[int32](0)}}},
	} {
		bad := &pqcv1alpha1.SecureSignPQC{Namespace: ns, Name: tc.name, Spec: tc.spec}
		if err := k8s.Create(ctx, bad); !apierrors.IsInvalid(err) {
			t.Errorf("%s: got %v, want Invalid", tc.name, err)
		}
	}
	for _, name := range []string{strings.Repeat("a", 60), "demo.tsa", "1demo"} {
		bad := &pqcv1alpha1.SecureSignPQC{Namespace: ns, Name: name, Spec: pqcv1alpha1.SecureSignPQCSpec{Version: "2.0"}}
		if err := k8s.Create(ctx, bad); !apierrors.IsInvalid(err) {
			t.Errorf("name %q: got %v, want Invalid", name, err)
		}
	}
	if err := k8s.Create(ctx, &pqcv1alpha1.SecureSignPQC{Namespace: ns, Name: strings.Repeat("a", 59), Spec: pqcv1alpha1.SecureSignPQCSpec{Version: "2.0"}}); err != nil {
		t.Errorf("59-character name: %v", err)
	}
}

// Every pair of parameter sets: a move to a weaker set needs
// acceptWeakerAlgorithm to name it and the next generation; any other move
// needs nothing.
func TestAlgorithmRule(t *testing.T) {
	ctx := context.Background()
	ns := createNamespace(t, "algorithm")
	algorithms := []pqcv1alpha1.Algorithm{pqcv1alpha1.MLDSA44, pqcv1alpha1.MLDSA65, pqcv1alpha1.MLDSA87}
	for _, from := range algorithms {
		for _, to := range algorithms {
			weaker := pki.Strength(to) < pki.Strength(from)
			name := strings.ToLower(fmt.Sprintf("%s-to-%s", from, to))
			t.Run(name, func(t *testing.T) {
				cr := newInstance(ns)
				cr.Name = name
				cr.Spec.TSA.Signing.Algorithm = from
				if err := k8s.Create(ctx, cr); err != nil {
					t.Fatal(err)
				}
				move := func(accept *pqcv1alpha1.WeakerAlgorithmAcceptance) error {
					c := cr.DeepCopy()
					c.Spec.TSA.Signing.Algorithm, c.Spec.TSA.Signing.AcceptWeakerAlgorithm = to, accept
					return k8s.Update(ctx, c)
				}
				if err := move(nil); weaker != apierrors.IsInvalid(err) || (!weaker && err != nil) {
					t.Fatalf("without acceptance: got %v, weaker=%v", err, weaker)
				}
				if !weaker {
					return
				}
				for _, bad := range []pqcv1alpha1.WeakerAlgorithmAcceptance{
					{Algorithm: from, SignerGeneration: 2},
					{Algorithm: to, SignerGeneration: 1}, // the generation already in use
					{Algorithm: to, SignerGeneration: 3}, // past the next generation
				} {
					if err := move(&bad); !apierrors.IsInvalid(err) {
						t.Fatalf("acceptance %+v: got %v, want Invalid", bad, err)
					}
				}
				if err := move(&pqcv1alpha1.WeakerAlgorithmAcceptance{Algorithm: to, SignerGeneration: 2}); err != nil {
					t.Fatalf("acceptance naming %s for generation 2: %v", to, err)
				}
			})
		}
	}
}

// An acceptance left in the spec from one downgrade does not pass a later
// one: it names a generation that is no longer above the current one.
func TestStaleAcceptanceRefused(t *testing.T) {
	ctx := context.Background()
	ns := createNamespace(t, "stale")
	cr := newInstance(ns)
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		algorithm pqcv1alpha1.Algorithm
		gen       int32
		accept    int32
		invalid   bool
	}{
		{pqcv1alpha1.MLDSA44, 1, 5, true},  // 65 to 44, accepted for a generation past the next
		{pqcv1alpha1.MLDSA44, 1, 2, false}, // accepted for the next generation, raised later
		{pqcv1alpha1.MLDSA87, 3, 2, false},
		{pqcv1alpha1.MLDSA44, 4, 2, true},  // 87 to 44 with the acceptance for generation 2
		{pqcv1alpha1.MLDSA44, 4, 5, true},  // raised to 4 but accepted for 5
		{pqcv1alpha1.MLDSA44, 6, 6, false}, // accepted for the generation this edit raises to
	}
	for _, step := range steps {
		got := getCR(t, ns)
		got.Spec.TSA.Signing.Algorithm, got.Spec.TSA.Signing.SignerGeneration = step.algorithm, step.gen
		got.Spec.TSA.Signing.AcceptWeakerAlgorithm = &pqcv1alpha1.WeakerAlgorithmAcceptance{Algorithm: pqcv1alpha1.MLDSA44, SignerGeneration: step.accept}
		if err := k8s.Update(ctx, got); apierrors.IsInvalid(err) != step.invalid || (!step.invalid && err != nil) {
			t.Fatalf("%s at generation %d accepted for %d: got %v, want invalid=%v", step.algorithm, step.gen, step.accept, err, step.invalid)
		}
	}
}

func getCR(t *testing.T, ns string) *pqcv1alpha1.SecureSignPQC {
	t.Helper()
	var cr pqcv1alpha1.SecureSignPQC
	if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "demo"}, &cr); err != nil {
		t.Fatal(err)
	}
	return &cr
}

func conditionIs(cr *pqcv1alpha1.SecureSignPQC, condType string, status metav1.ConditionStatus, reason string) error {
	c := meta.FindStatusCondition(cr.Status.Conditions, condType)
	if c == nil {
		return fmt.Errorf("no %s condition", condType)
	}
	if c.Status != status || (reason != "" && c.Reason != reason) {
		return fmt.Errorf("%s is %s/%s (%s), want %s/%s", condType, c.Status, c.Reason, c.Message, status, reason)
	}
	return nil
}

// markAvailable plays the Deployment controller, which envtest lacks, for
// the TSA template that mounts the newest signer Secret.
func markAvailable(t *testing.T, ns string) {
	t.Helper()
	ctx := context.Background()
	eventually(t, 30*time.Second, "TSA Deployment marked available", func() error {
		newest, err := newestSigner(ctx, ns)
		if err != nil {
			return err
		}
		var d appsv1.Deployment
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); err != nil {
			return err
		}
		mounted := ""
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Name == "signer" && v.Secret != nil {
				mounted = v.Secret.SecretName
			}
		}
		if mounted != newest {
			return fmt.Errorf("template mounts %q, newest signer is %q", mounted, newest)
		}
		n := ptr.Deref(d.Spec.Replicas, 1)
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: n, UpdatedReplicas: n, ReadyReplicas: n, AvailableReplicas: n}
		return k8s.Status().Update(ctx, &d)
	})
}

// newestSigner names the signer Secret with the highest key generation.
func newestSigner(ctx context.Context, ns string) (string, error) {
	var all corev1.SecretList
	if err := k8s.List(ctx, &all, client.InNamespace(ns), client.MatchingLabels{controller.LabelKeyRole: controller.RoleTSASigner}); err != nil {
		return "", err
	}
	newest, top := "", int64(0)
	for _, s := range all.Items {
		g, err := strconv.ParseInt(s.Labels[controller.LabelKeyGeneration], 10, 32)
		if err != nil {
			return "", fmt.Errorf("signer %s: %w", s.Name, err)
		}
		if g > top {
			newest, top = s.Name, g
		}
	}
	if newest == "" {
		return "", errors.New("no signer Secret yet")
	}
	return newest, nil
}

func signerSecret(t *testing.T, ns string, generation int32) *corev1.Secret {
	t.Helper()
	return getSecret(t, ns, controller.TSASignerSecretName("demo", generation))
}

func caSecret(t *testing.T, ns string) *corev1.Secret {
	t.Helper()
	return getSecret(t, ns, controller.TSACASecretName("demo"))
}

func getSecret(t *testing.T, ns, name string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

// decodeSigner checks a signer Secret against the instance's CA Secret.
func decodeSigner(t *testing.T, ns string, generation int32) *pki.TSAChain {
	t.Helper()
	ca, err := pki.DecodeTSACA(caSecret(t, ns).Data)
	if err != nil {
		t.Fatalf("CA secret: %v", err)
	}
	chain, err := pki.DecodeTSAChain(signerSecret(t, ns, generation).Data, ca)
	if err != nil {
		t.Fatalf("signer secret %d: %v", generation, err)
	}
	return chain
}

func keySecrets(t *testing.T, ns string) []string {
	t.Helper()
	var all corev1.SecretList
	if err := k8s.List(context.Background(), &all, client.InNamespace(ns), client.MatchingLabels{controller.LabelInstance: "demo"}); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(all.Items))
	for _, s := range all.Items {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	return names
}

func TestTSAInstall(t *testing.T) {
	ctx := context.Background()
	opns := createNamespace(t, "op")
	startOperator(t, opns, nil)
	ns := createNamespace(t, "install")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}

	var d appsv1.Deployment
	eventually(t, 30*time.Second, "TSA Deployment", func() error {
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d)
	})
	profiles, _ := supported.Load()
	p, _ := profiles.Lookup("2.0")
	wantImage, _ := p.Image(versions.ImageTSA)
	if got := d.Spec.Template.Spec.Containers[0].Image; got != wantImage {
		t.Errorf("image %s, want %s", got, wantImage)
	}
	if len(d.OwnerReferences) != 1 || d.OwnerReferences[0].Kind != "SecureSignPQC" {
		t.Errorf("owner references %v", d.OwnerReferences)
	}
	var svc corev1.Service
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &svc); err != nil {
		t.Fatal(err)
	}

	decodeSigner(t, ns, 1)
	sec := signerSecret(t, ns, 1)
	for _, s := range []*corev1.Secret{sec, caSecret(t, ns)} {
		if len(s.OwnerReferences) != 0 {
			t.Errorf("%s has an owner; deleting the instance would delete its keys", s.Name)
		}
	}

	eventually(t, 10*time.Second, "Ready False while rolling out", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionTSAReady, metav1.ConditionFalse, "Progressing")
	})
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "AllComponentsReady"); err != nil {
			return err
		}
		if err := conditionIs(cr, pqcv1alpha1.ConditionDegraded, metav1.ConditionFalse, ""); err != nil {
			return err
		}
		if cr.Status.Version != "2.0" || cr.Status.TSA.URL != "http://demo-tsa."+ns+".svc:3000" {
			return fmt.Errorf("status %+v", cr.Status)
		}
		keys := cr.Status.TSA
		if keys.CA == nil || keys.CA.Algorithm != pqcv1alpha1.MLDSA65 || len(keys.Signers) != 1 ||
			keys.Signers[0].Generation != 1 || keys.Signers[0].Stage != pqcv1alpha1.KeyActive || keys.Signers[0].Algorithm != pqcv1alpha1.MLDSA65 {
			return fmt.Errorf("tsa key status %+v", keys)
		}
		return nil
	})

	// A deleted child is recreated; the keys are not.
	if err := k8s.Delete(ctx, &d); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "Deployment recreated", func() error {
		var again appsv1.Deployment
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &again); err != nil {
			return err
		}
		if again.UID == d.UID {
			return errors.New("still the old Deployment")
		}
		return nil
	})
	if after := signerSecret(t, ns, 1); !bytes.Equal(after.Data[pki.KeyPEM], sec.Data[pki.KeyPEM]) || after.UID != sec.UID {
		t.Fatal("signer Secret changed when the Deployment was recreated")
	}
	if got, want := keySecrets(t, ns), []string{"demo-tsa-ca", "demo-tsa-signer-1"}; !slices.Equal(got, want) {
		t.Fatalf("key Secrets %v, want %v", got, want)
	}
}

// createKeys creates a CA Secret and a generation-1 signer Secret as an
// administrator restoring keys would.
func createKeys(t *testing.T, ns string, ca *pki.TSACA, leaf *pki.TSAChain) (caSec, signerSec *corev1.Secret) {
	t.Helper()
	// The key labels are spelt out: they are what the README tells an
	// administrator to set, so a change to them fails here.
	labels := func(role string) map[string]string {
		return map[string]string{
			controller.LabelInstance: "demo", controller.LabelManagedBy: controller.ManagedBy,
			"pqc.rhtas.redhat.com/key-role": role,
		}
	}
	caData, err := ca.Encode()
	if err != nil {
		t.Fatal(err)
	}
	leafData, err := leaf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	caSec = &corev1.Secret{Namespace: ns, Name: controller.TSACASecretName("demo"), Labels: labels("tsa-ca"), Data: caData}
	signerSec = &corev1.Secret{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1), Labels: labels("tsa-signer"), Data: leafData}
	signerSec.Labels["pqc.rhtas.redhat.com/key-generation"] = "1"
	for _, s := range []*corev1.Secret{caSec, signerSec} {
		if err := k8s.Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	return caSec, signerSec
}

func newCA(t *testing.T, a pqcv1alpha1.Algorithm) *pki.TSACA {
	t.Helper()
	ca, err := pki.NewTSACA(a, "preexisting", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func issue(t *testing.T, ca *pki.TSACA, a pqcv1alpha1.Algorithm) *pki.TSAChain {
	t.Helper()
	leaf, err := ca.IssueLeaf(a, "preexisting", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// Restored keys are used as they are, even at a parameter set other than
// spec.tsa.signing.algorithm: that names only the next key.
func TestExistingSignerIsUsed(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "existing")
	ca := newCA(t, pqcv1alpha1.MLDSA87)
	preCA, pre := createKeys(t, ns, ca, issue(t, ca, pqcv1alpha1.MLDSA44))
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "TSA Deployment", func() error {
		var d appsv1.Deployment
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d)
	})
	if got := signerSecret(t, ns, 1); got.UID != pre.UID || !bytes.Equal(got.Data[pki.KeyPEM], pre.Data[pki.KeyPEM]) {
		t.Fatal("pre-existing signer Secret was replaced")
	}
	if got := caSecret(t, ns); got.UID != preCA.UID {
		t.Fatal("pre-existing CA Secret was replaced")
	}
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "key status", func() error {
		keys := getCR(t, ns).Status.TSA
		if keys.CA == nil || keys.CA.Algorithm != pqcv1alpha1.MLDSA87 || len(keys.Signers) != 1 || keys.Signers[0].Algorithm != pqcv1alpha1.MLDSA44 {
			return fmt.Errorf("tsa key status %+v", keys)
		}
		return nil
	})
}

// A signer not issued by the instance's CA is reported, not used or
// replaced.
func TestInvalidSignerDegrades(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "invalid")
	_, pre := createKeys(t, ns, newCA(t, pqcv1alpha1.MLDSA65), issue(t, newCA(t, pqcv1alpha1.MLDSA65), pqcv1alpha1.MLDSA65))
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "Degraded InvalidSigner", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionDegraded, metav1.ConditionTrue, "InvalidSigner")
	})
	var d appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); !apierrors.IsNotFound(err) {
		t.Fatalf("TSA deployed with an unusable signer: %v", err)
	}
	if got := signerSecret(t, ns, 1); got.UID != pre.UID || !bytes.Equal(got.Data[pki.KeyPEM], pre.Data[pki.KeyPEM]) {
		t.Fatal("operator replaced an unusable signer Secret instead of reporting it")
	}
}

func setSpec(t *testing.T, ns string, edit func(*pqcv1alpha1.SecureSignPQCSpec)) {
	t.Helper()
	eventually(t, 10*time.Second, "spec update", func() error {
		cr := getCR(t, ns)
		edit(&cr.Spec)
		return k8s.Update(context.Background(), cr)
	})
}

func signerStatus(cr *pqcv1alpha1.SecureSignPQC) string {
	parts := make([]string, 0, len(cr.Status.TSA.Signers))
	for _, k := range cr.Status.TSA.Signers {
		parts = append(parts, fmt.Sprintf("%d:%s:%s", k.Generation, k.Algorithm, k.Stage))
	}
	return strings.Join(parts, ",")
}

// Raising signerGeneration issues a new key at the new parameter set from
// the same CA, moves the pods to it, and deletes the old private key only
// once every pod uses the new one.
func TestTSALeafRotation(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "rotate")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "signer 1", func() error {
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1)}, &corev1.Secret{})
	})
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready on signer 1", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	ca := caSecret(t, ns)
	first := decodeSigner(t, ns, 1)

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) {
		s.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA87
		s.TSA.Signing.SignerGeneration = 2
	})
	eventually(t, 30*time.Second, "signer 2 pending", func() error {
		if got := signerStatus(getCR(t, ns)); got != "2:ML-DSA-87:Pending,1:ML-DSA-65:Active" {
			return fmt.Errorf("signers %s", got)
		}
		return nil
	})
	second := decodeSigner(t, ns, 2)
	if a, _ := pki.AlgorithmOf(second.Leaf.PublicKey); a != pqcv1alpha1.MLDSA87 {
		t.Fatalf("signer 2 is %s, want ML-DSA-87", a)
	}
	var d appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); err != nil {
		t.Fatal(err)
	}
	if got := d.Spec.Template.Spec.Volumes[0].Secret.SecretName; got != controller.TSASignerSecretName("demo", 2) {
		t.Fatalf("pods mount %s", got)
	}
	// The pods have not rolled: the old key must stay, and Ready drops.
	time.Sleep(2 * time.Second)
	signerSecret(t, ns, 1)
	if err := conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionFalse, ""); err != nil {
		t.Fatal(err)
	}

	markAvailable(t, ns)
	eventually(t, 30*time.Second, "signer 1 retired", func() error {
		cr := getCR(t, ns)
		if got := signerStatus(cr); got != "2:ML-DSA-87:Active,1:ML-DSA-65:Retired" {
			return fmt.Errorf("signers %s", got)
		}
		if cr.Status.TSA.Signers[1].RetiredAt == nil || cr.Status.TSA.Signers[1].SerialNumber != first.Leaf.SerialNumber.Text(16) {
			return fmt.Errorf("retired entry %+v", cr.Status.TSA.Signers[1])
		}
		return conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	if got, want := keySecrets(t, ns), []string{"demo-tsa-ca", "demo-tsa-signer-2"}; !slices.Equal(got, want) {
		t.Fatalf("key Secrets %v, want %v", got, want)
	}
	if got := caSecret(t, ns); got.UID != ca.UID {
		t.Fatal("CA Secret replaced by a leaf rotation")
	}
	if cr := getCR(t, ns); cr.Status.TSA.CA.Algorithm != pqcv1alpha1.MLDSA65 {
		t.Fatalf("CA status %+v; a leaf rotation does not change the CA", cr.Status.TSA.CA)
	}
}

// The CRD rule sees only old and new spec, so an acceptance can be moved
// to another generation before the generation is raised.
func TestWeakerSignerNeedsAcceptance(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "weaker")
	cr := newInstance(ns)
	cr.Spec.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA87
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "signer 1", func() error {
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1)}, &corev1.Secret{})
	})
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) {
		s.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA44
		s.TSA.Signing.AcceptWeakerAlgorithm = &pqcv1alpha1.WeakerAlgorithmAcceptance{Algorithm: pqcv1alpha1.MLDSA44, SignerGeneration: 2}
	})
	// Admission only checks the acceptance when the algorithm changes.
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.AcceptWeakerAlgorithm.SignerGeneration = 3 })
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.SignerGeneration = 2 })
	eventually(t, 30*time.Second, "blocked", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "WeakerAlgorithmNotAccepted")
	})
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 2)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("weaker signer created without acceptance: %v", err)
	}
	if err := conditionIs(getCR(t, ns), pqcv1alpha1.ConditionDegraded, metav1.ConditionTrue, ""); err == nil {
		t.Fatal("a refused downgrade marked the operator Degraded")
	}

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.AcceptWeakerAlgorithm.SignerGeneration = 2 })
	eventually(t, 30*time.Second, "signer 2", func() error {
		if got := signerStatus(getCR(t, ns)); got != "2:ML-DSA-44:Pending,1:ML-DSA-87:Active" {
			return fmt.Errorf("signers %s", got)
		}
		return nil
	})
}

// A recreated instance whose generation is below its newest signer Secret
// waits for the spec instead of issuing a key and stranding the newer one.
func TestRecreatedInstanceBehindGeneration(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "recreate")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "signer 1", func() error {
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1)}, &corev1.Secret{})
	})
	markAvailable(t, ns)
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.SignerGeneration = 2 })
	eventually(t, 30*time.Second, "signer 2", func() error {
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 2)}, &corev1.Secret{})
	})
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "signer 1 deleted", func() error {
		if got, want := keySecrets(t, ns), []string{"demo-tsa-ca", "demo-tsa-signer-2"}; !slices.Equal(got, want) {
			return fmt.Errorf("key Secrets %v", got)
		}
		return nil
	})
	ca, second := caSecret(t, ns), signerSecret(t, ns, 2)

	cr := getCR(t, ns)
	if err := k8s.Delete(ctx, cr); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "instance gone", gone(cr))
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "blocked", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "SignerGenerationBehind")
	})
	time.Sleep(2 * time.Second)
	if got, want := keySecrets(t, ns), []string{"demo-tsa-ca", "demo-tsa-signer-2"}; !slices.Equal(got, want) {
		t.Fatalf("key Secrets %v, want %v", got, want)
	}

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.SignerGeneration = 2 })
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready on signer 2", func() error {
		cr := getCR(t, ns)
		if got := signerStatus(cr); got != "2:ML-DSA-65:Active" {
			return fmt.Errorf("signers %s", got)
		}
		return conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	if got := signerSecret(t, ns, 2); got.UID != second.UID {
		t.Fatal("signer 2 Secret replaced")
	}
	if got := caSecret(t, ns); got.UID != ca.UID {
		t.Fatal("CA Secret replaced")
	}
}

// A CA close to expiry is reported, with one Warning event, and does not
// stop the TSA becoming Ready.
func TestExpiringCAReported(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "expiring")
	issued := time.Now().Add(-15*365*24*time.Hour + 30*24*time.Hour)
	ca, err := pki.NewTSACA(pqcv1alpha1.MLDSA65, "preexisting", issued)
	if err != nil {
		t.Fatal(err)
	}
	createKeys(t, ns, ca, issue(t, ca, pqcv1alpha1.MLDSA65))
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "CertificatesExpiring", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionCertificatesExpiring, metav1.ConditionTrue, "CAExpiring"); err != nil {
			return err
		}
		return conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	eventually(t, 30*time.Second, "CAExpiring event", func() error {
		var list eventsv1.EventList
		if err := k8s.List(ctx, &list, client.InNamespace(ns)); err != nil {
			return err
		}
		n := 0
		for _, e := range list.Items {
			if e.Regarding.Kind == "SecureSignPQC" && e.Reason == "CAExpiring" && e.Type == corev1.EventTypeWarning {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("%d CAExpiring events", n)
		}
		return nil
	})
}

// The FIPS annotation sets the TSA pods' fips140 mode. A value the TSA would
// refuse holds the instance and leaves the running pods as they are.
func TestFIPSAnnotation(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "fips")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	godebug := func(want string) func() error {
		return func() error {
			var d appsv1.Deployment
			if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); err != nil {
				return err
			}
			var got []string
			for _, e := range d.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "GODEBUG" {
					got = append(got, e.Value)
				}
			}
			if !slices.Equal(got, []string{want}) {
				return fmt.Errorf("GODEBUG %v, want %s", got, want)
			}
			return nil
		}
	}
	annotate := func(v *string) {
		t.Helper()
		cr := getCR(t, ns)
		patch := client.MergeFrom(cr.DeepCopy())
		if v == nil {
			delete(cr.Annotations, pqcv1alpha1.FIPSAnnotation)
		} else {
			metav1.SetMetaDataAnnotation(&cr.ObjectMeta, pqcv1alpha1.FIPSAnnotation, *v)
		}
		if err := k8s.Patch(ctx, cr, patch); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, 30*time.Second, "default auto", godebug("fips140=auto"))
	annotate(new("only"))
	eventually(t, 30*time.Second, "only", godebug("fips140=only"))
	annotate(new("off"))
	eventually(t, 30*time.Second, "InvalidFIPSMode", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "InvalidFIPSMode")
	})
	if err := godebug("fips140=only")(); err != nil {
		t.Fatalf("invalid mode applied: %v", err)
	}
	annotate(nil)
	eventually(t, 30*time.Second, "auto again", godebug("fips140=auto"))
}

// The expiry check runs on resync, with no change to the instance: a signer
// that enters the warning window while nothing else happens is reported.
func TestExpiryCheckedOnResync(t *testing.T) {
	ctx := context.Background()
	ns := createNamespace(t, "resync")
	ca := newCA(t, pqcv1alpha1.MLDSA65)
	leaf, err := ca.IssueLeaf(pqcv1alpha1.MLDSA65, "preexisting", time.Now().Add(-10*365*24*time.Hour+time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	createKeys(t, ns, ca, leaf)
	// The leaf enters the window about 10 s from now.
	warning := time.Until(leaf.Leaf.NotAfter) - 10*time.Second
	startOperator(t, createNamespace(t, "op"), func(o *Options) {
		o.Effective.SyncPeriod = 2 * time.Second
		o.Effective.ExpiryWarning = warning
	})
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	markAvailable(t, ns)
	eventually(t, 5*time.Second, "not expiring yet", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionCertificatesExpiring, metav1.ConditionFalse, "NotExpiring")
	})
	eventually(t, 30*time.Second, "SignerExpiring after resync", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionCertificatesExpiring, metav1.ConditionTrue, "SignerExpiring")
	})
}
