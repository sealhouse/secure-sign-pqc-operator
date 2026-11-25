package operator

import (
	"bytes"
	"context"
	"crypto/x509"
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

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"

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
	cr = getCR(t, ns)
	if s := cr.Spec.TSA.Signing; s.IntermediateGeneration != 1 || s.RootGeneration != 1 {
		t.Errorf("default CA generations %d/%d, want 1/1", s.RootGeneration, s.IntermediateGeneration)
	}
	cr.Spec.TSA.Signing.IntermediateGeneration, cr.Spec.TSA.Signing.RootGeneration = 3, 2
	if err := k8s.Update(ctx, cr); err != nil {
		t.Errorf("raise CA generations: %v", err)
	}
	for name, edit := range map[string]func(*pqcv1alpha1.SigningSpec){
		"intermediateGeneration": func(s *pqcv1alpha1.SigningSpec) { s.IntermediateGeneration = 2 },
		"rootGeneration":         func(s *pqcv1alpha1.SigningSpec) { s.RootGeneration = 1 },
		"empty acceptance": func(s *pqcv1alpha1.SigningSpec) {
			s.AcceptWeakerAlgorithm = &pqcv1alpha1.WeakerAlgorithmAcceptance{Algorithm: pqcv1alpha1.MLDSA44}
		},
	} {
		c := getCR(t, ns)
		edit(&c.Spec.TSA.Signing)
		if err := k8s.Update(ctx, c); !apierrors.IsInvalid(err) {
			t.Errorf("%s: got %v, want Invalid", name, err)
		}
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
	algorithms := pki.Algorithms()
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
				for _, bad := range []pqcv1alpha1.WeakerAlgorithmAcceptance{
					{Algorithm: to, IntermediateGeneration: 1},
					{Algorithm: to, RootGeneration: 3},
				} {
					if err := move(&bad); !apierrors.IsInvalid(err) {
						t.Fatalf("acceptance %+v: got %v, want Invalid", bad, err)
					}
				}
				for i, good := range []pqcv1alpha1.WeakerAlgorithmAcceptance{
					{Algorithm: to, IntermediateGeneration: 2},
					{Algorithm: to, RootGeneration: 2},
					{Algorithm: to, SignerGeneration: 2},
				} {
					c := newInstance(ns)
					c.Name = fmt.Sprintf("%s-%d", name, i)
					c.Spec.TSA.Signing.Algorithm = from
					if err := k8s.Create(ctx, c); err != nil {
						t.Fatal(err)
					}
					c.Spec.TSA.Signing.Algorithm, c.Spec.TSA.Signing.AcceptWeakerAlgorithm = to, &good
					if err := k8s.Update(ctx, c); err != nil {
						t.Fatalf("acceptance %+v: %v", good, err)
					}
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

// newestSigner names the signer Secret with the highest key generation,
// under the newest CA when a rotation issued one generation twice.
func newestSigner(ctx context.Context, ns string) (string, error) {
	var all corev1.SecretList
	if err := k8s.List(ctx, &all, client.InNamespace(ns), client.MatchingLabels{controller.LabelKeyRole: controller.RoleTSASigner}); err != nil {
		return "", err
	}
	newest, top := "", [3]int64{}
	for _, s := range all.Items {
		var key [3]int64
		for i, l := range []string{controller.LabelKeyGeneration, controller.LabelRootGeneration, controller.LabelIntermediateGeneration} {
			v, ok := s.Labels[l]
			if !ok && i > 0 {
				v = "1"
			}
			g, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				return "", fmt.Errorf("signer %s: %w", s.Name, err)
			}
			key[i] = g
		}
		if slices.Compare(key[:], top[:]) > 0 {
			newest, top = s.Name, key
		}
	}
	if newest == "" {
		return "", errors.New("no signer Secret yet")
	}
	return newest, nil
}

func signerSecret(t *testing.T, ns string, root, intermediate, generation int32) *corev1.Secret {
	t.Helper()
	return getSecret(t, ns, controller.TSASignerSecretName("demo", root, intermediate, generation))
}

func caSecret(t *testing.T, ns string, root, intermediate int32) *corev1.Secret {
	t.Helper()
	return getSecret(t, ns, controller.TSAIntermediateSecretName("demo", root, intermediate))
}

func getSecret(t *testing.T, ns, name string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

// decodeSigner checks a signer Secret against its intermediate's Secret.
func decodeSigner(t *testing.T, ns string, root, intermediate, generation int32) *pki.TSAChain {
	t.Helper()
	ca, err := pki.DecodeCA(caSecret(t, ns, root, intermediate).Data)
	if err != nil {
		t.Fatalf("CA secret: %v", err)
	}
	chain, err := pki.DecodeTSAChain(signerSecret(t, ns, root, intermediate, generation).Data, ca)
	if err != nil {
		t.Fatalf("signer secret %d-%d-%d: %v", root, intermediate, generation, err)
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

// publishedIntermediates returns the serial numbers of the intermediates in
// the instance's trusted root, oldest first, with "-retired" after one
// that has a validity end.
func publishedIntermediates(ctx context.Context, ns string) ([]string, error) {
	var cm corev1.ConfigMap
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TrustedRootName("demo")}, &cm); err != nil {
		return nil, err
	}
	var tr prototrustroot.TrustedRoot
	if err := protojson.Unmarshal([]byte(cm.Data[controller.TrustedRootKey]), &tr); err != nil {
		return nil, err
	}
	var out []string
	for _, ta := range tr.GetTimestampAuthorities() {
		certs := ta.GetCertChain().GetCertificates()
		if len(certs) != 2 {
			return nil, fmt.Errorf("entry %s has %d certificates, want intermediate and root", ta.GetSubject().GetCommonName(), len(certs))
		}
		c, err := x509.ParseCertificate(certs[0].GetRawBytes())
		if err != nil {
			return nil, err
		}
		entry := c.SerialNumber.Text(16)
		if ta.GetValidFor().End != nil {
			entry += "-retired"
		}
		out = append(out, entry)
	}
	return out, nil
}

func serial(c *x509.Certificate) string { return c.SerialNumber.Text(16) }

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

	chain := decodeSigner(t, ns, 1, 1, 1)
	sec := signerSecret(t, ns, 1, 1, 1)
	for _, s := range []*corev1.Secret{sec, caSecret(t, ns, 1, 1), getSecret(t, ns, controller.TSARootSecretName("demo", 1))} {
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
		if ca := activeIntermediate(cr); ca == nil || ca.Algorithm != pqcv1alpha1.MLDSA65 || len(keys.Signers) != 1 ||
			keys.Signers[0].Generation != 1 || keys.Signers[0].Stage != pqcv1alpha1.KeyActive || keys.Signers[0].Algorithm != pqcv1alpha1.MLDSA65 {
			return fmt.Errorf("tsa key status %+v", keys)
		}
		if got := caStages(cr); got != "Root 1-0 Active,Intermediate 1-1 Active" {
			return fmt.Errorf("cas %s", got)
		}
		return conditionIs(cr, pqcv1alpha1.ConditionTSACARotation, metav1.ConditionFalse, "NoRotation")
	})
	published, err := publishedIntermediates(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{serial(chain.Intermediate)}; !slices.Equal(published, want) {
		t.Fatalf("trusted root lists %v, want %v", published, want)
	}
	var record corev1.ConfigMap
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAChainName("demo", 1, 1)}, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.OwnerReferences) != 0 {
		t.Error("chain record has an owner; deleting the instance would lose retired chains")
	}

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
	if after := signerSecret(t, ns, 1, 1, 1); !bytes.Equal(after.Data[pki.KeyPEM], sec.Data[pki.KeyPEM]) || after.UID != sec.UID {
		t.Fatal("signer Secret changed when the Deployment was recreated")
	}
	if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-1-1", "demo-tsa-root-1", "demo-tsa-signer-1-1-1"}; !slices.Equal(got, want) {
		t.Fatalf("key Secrets %v, want %v", got, want)
	}
}

// keyLabels are the labels the README tells an administrator restoring keys
// to set; they are spelt out so a change to them fails here.
func keyLabels(role string, gens ...string) map[string]string {
	l := map[string]string{
		controller.LabelInstance: "demo", controller.LabelManagedBy: controller.ManagedBy,
		"pqc.rhtas.redhat.com/key-role": role,
	}
	for i, k := range []string{"pqc.rhtas.redhat.com/root-generation", "pqc.rhtas.redhat.com/intermediate-generation", "pqc.rhtas.redhat.com/key-generation"} {
		if i < len(gens) {
			l[k] = gens[i]
		}
	}
	return l
}

// createKeys creates root 1, intermediate 1-1 and signer 1-1-1 Secrets as
// an administrator restoring keys would.
func createKeys(t *testing.T, ns string, root *pki.Root, ca *pki.CA, leaf *pki.TSAChain) (caSec, signerSec *corev1.Secret) {
	t.Helper()
	rootData, err := root.Encode()
	if err != nil {
		t.Fatal(err)
	}
	caData, err := ca.Encode()
	if err != nil {
		t.Fatal(err)
	}
	leafData, err := leaf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	rootSec := &corev1.Secret{Namespace: ns, Name: controller.TSARootSecretName("demo", 1), Labels: keyLabels("tsa-root", "1"), Data: rootData}
	caSec = &corev1.Secret{Namespace: ns, Name: controller.TSAIntermediateSecretName("demo", 1, 1), Labels: keyLabels("tsa-intermediate", "1", "1"), Data: caData}
	signerSec = &corev1.Secret{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1, 1, 1), Labels: keyLabels("tsa-signer", "1", "1", "1"), Data: leafData}
	for _, s := range []*corev1.Secret{rootSec, caSec, signerSec} {
		if err := k8s.Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	return caSec, signerSec
}

func newCA(t *testing.T, a pqcv1alpha1.Algorithm) (*pki.Root, *pki.CA) {
	t.Helper()
	return newCAAt(t, a, time.Now(), time.Now())
}

func newCAAt(t *testing.T, a pqcv1alpha1.Algorithm, rootIssued, intIssued time.Time) (*pki.Root, *pki.CA) {
	t.Helper()
	root, err := pki.NewRoot(a, "preexisting root", rootIssued)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := root.IssueIntermediate(a, "preexisting intermediate", pki.TSAIntermediateEKU, intIssued)
	if err != nil {
		t.Fatal(err)
	}
	return root, ca
}

func issue(t *testing.T, ca *pki.CA, a pqcv1alpha1.Algorithm) *pki.TSAChain {
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
	root, ca := newCA(t, pqcv1alpha1.MLDSA87)
	preCA, pre := createKeys(t, ns, root, ca, issue(t, ca, pqcv1alpha1.MLDSA44))
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "TSA Deployment", func() error {
		var d appsv1.Deployment
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d)
	})
	if got := signerSecret(t, ns, 1, 1, 1); got.UID != pre.UID || !bytes.Equal(got.Data[pki.KeyPEM], pre.Data[pki.KeyPEM]) {
		t.Fatal("pre-existing signer Secret was replaced")
	}
	if got := caSecret(t, ns, 1, 1); got.UID != preCA.UID {
		t.Fatal("pre-existing CA Secret was replaced")
	}
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "key status", func() error {
		cr := getCR(t, ns)
		keys := cr.Status.TSA
		if ca := activeIntermediate(cr); ca == nil || ca.Algorithm != pqcv1alpha1.MLDSA87 || len(keys.Signers) != 1 || keys.Signers[0].Algorithm != pqcv1alpha1.MLDSA44 {
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
	root, ca := newCA(t, pqcv1alpha1.MLDSA65)
	_, other := newCA(t, pqcv1alpha1.MLDSA65)
	_, pre := createKeys(t, ns, root, ca, issue(t, other, pqcv1alpha1.MLDSA65))
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
	if got := signerSecret(t, ns, 1, 1, 1); got.UID != pre.UID || !bytes.Equal(got.Data[pki.KeyPEM], pre.Data[pki.KeyPEM]) {
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

func caStages(cr *pqcv1alpha1.SecureSignPQC) string {
	parts := make([]string, 0, len(cr.Status.TSA.CAs))
	for _, k := range cr.Status.TSA.CAs {
		parts = append(parts, k.String())
	}
	return strings.Join(parts, ",")
}

// activeIntermediate is the newest Active intermediate in status, or nil.
func activeIntermediate(cr *pqcv1alpha1.SecureSignPQC) *pqcv1alpha1.CAStatus {
	for i, k := range cr.Status.TSA.CAs {
		if k.Kind == pqcv1alpha1.CAIntermediate && k.Stage == pqcv1alpha1.KeyActive {
			return &cr.Status.TSA.CAs[i]
		}
	}
	return nil
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
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1, 1, 1)}, &corev1.Secret{})
	})
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready on signer 1", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	ca := caSecret(t, ns, 1, 1)
	first := decodeSigner(t, ns, 1, 1, 1)
	published, err := publishedIntermediates(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}

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
	second := decodeSigner(t, ns, 1, 1, 2)
	if a, _ := pki.AlgorithmOf(second.Leaf.PublicKey); a != pqcv1alpha1.MLDSA87 {
		t.Fatalf("signer 2 is %s, want ML-DSA-87", a)
	}
	var d appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); err != nil {
		t.Fatal(err)
	}
	if got := d.Spec.Template.Spec.Volumes[0].Secret.SecretName; got != controller.TSASignerSecretName("demo", 1, 1, 2) {
		t.Fatalf("pods mount %s", got)
	}
	// The pods have not rolled: the old key must stay, and Ready drops.
	time.Sleep(2 * time.Second)
	signerSecret(t, ns, 1, 1, 1)
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
	if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-1-1", "demo-tsa-root-1", "demo-tsa-signer-1-1-2"}; !slices.Equal(got, want) {
		t.Fatalf("key Secrets %v, want %v", got, want)
	}
	if got := caSecret(t, ns, 1, 1); got.UID != ca.UID {
		t.Fatal("CA Secret replaced by a leaf rotation")
	}
	if after, err := publishedIntermediates(ctx, ns); err != nil || !slices.Equal(after, published) {
		t.Fatalf("trusted root %v, %v changed by a leaf rotation; was %v", after, err, published)
	}
	if ca := activeIntermediate(getCR(t, ns)); ca == nil || ca.Algorithm != pqcv1alpha1.MLDSA65 {
		t.Fatalf("CA status %+v; a leaf rotation does not change the CA", ca)
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
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1, 1, 1)}, &corev1.Secret{})
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
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1, 1, 2)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
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
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1, 1, 1)}, &corev1.Secret{})
	})
	markAvailable(t, ns)
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.SignerGeneration = 2 })
	eventually(t, 30*time.Second, "signer 2", func() error {
		return k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSASignerSecretName("demo", 1, 1, 2)}, &corev1.Secret{})
	})
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "signer 1 deleted", func() error {
		if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-1-1", "demo-tsa-root-1", "demo-tsa-signer-1-1-2"}; !slices.Equal(got, want) {
			return fmt.Errorf("key Secrets %v", got)
		}
		return nil
	})
	ca, second := caSecret(t, ns, 1, 1), signerSecret(t, ns, 1, 1, 2)

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
	if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-1-1", "demo-tsa-root-1", "demo-tsa-signer-1-1-2"}; !slices.Equal(got, want) {
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
	if got := signerSecret(t, ns, 1, 1, 2); got.UID != second.UID {
		t.Fatal("signer 2 Secret replaced")
	}
	if got := caSecret(t, ns, 1, 1); got.UID != ca.UID {
		t.Fatal("CA Secret replaced")
	}
}

// A CA close to expiry is reported, with one Warning event, and does not
// stop the TSA becoming Ready.
func TestExpiringCAReported(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "expiring")
	root, ca := newCAAt(t, pqcv1alpha1.MLDSA65, time.Now(), time.Now().Add(-pki.IntermediateValidity+30*24*time.Hour))
	createKeys(t, ns, root, ca, issue(t, ca, pqcv1alpha1.MLDSA65))
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
	root, ca := newCA(t, pqcv1alpha1.MLDSA65)
	leaf, err := ca.IssueLeaf(pqcv1alpha1.MLDSA65, "preexisting", time.Now().Add(-pki.LeafValidity+time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	createKeys(t, ns, root, ca, leaf)
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

// mountedSigner names the signer Secret the TSA pod template mounts.
func mountedSigner(ctx context.Context, ns string) (string, error) {
	var d appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); err != nil {
		return "", err
	}
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Name == "signer" && v.Secret != nil {
			return v.Secret.SecretName, nil
		}
	}
	return "", errors.New("no signer volume")
}

// readyOn waits for the instance to be Ready with the pods on signer.
func readyOn(t *testing.T, ns, signer string) {
	t.Helper()
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready on "+signer, func() error {
		got, err := mountedSigner(context.Background(), ns)
		if err != nil {
			return err
		}
		if got != signer {
			return fmt.Errorf("pods mount %s", got)
		}
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
}

// rotationPending waits for signer to be mounted while the previous keys
// still exist, and checks that the trusted root already lists its
// intermediate: the TSA must not sign with a chain clients cannot verify.
func rotationPending(t *testing.T, ns string, root, intermediate int32, signer string) {
	t.Helper()
	ctx := context.Background()
	eventually(t, 30*time.Second, signer+" mounted", func() error {
		got, err := mountedSigner(ctx, ns)
		if err != nil {
			return err
		}
		if got != signer {
			return fmt.Errorf("pods mount %s", got)
		}
		return nil
	})
	ca, err := pki.DecodeCA(caSecret(t, ns, root, intermediate).Data)
	if err != nil {
		t.Fatal(err)
	}
	published, err := publishedIntermediates(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(published, serial(ca.Intermediate)) {
		t.Fatalf("pods mount %s, but the trusted root lists only %v", signer, published)
	}
	eventually(t, 30*time.Second, "rotation rolling out", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionTSACARotation, metav1.ConditionTrue, "RollingOut"); err != nil {
			return err
		}
		return conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "")
	})
}

// Raising intermediateGeneration issues an intermediate under the same root
// and a signer from it, publishes the intermediate before the pods use it,
// and retires the old signer and intermediate once every pod moved. The
// old intermediate stays in the trusted root with a validity end.
func TestTSAIntermediateRotation(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "introtate")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	readyOn(t, ns, controller.TSASignerSecretName("demo", 1, 1, 1))
	root := getSecret(t, ns, controller.TSARootSecretName("demo", 1))
	old := decodeSigner(t, ns, 1, 1, 1)

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) {
		s.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA87
		s.TSA.Signing.IntermediateGeneration = 2
	})
	rotationPending(t, ns, 1, 2, controller.TSASignerSecretName("demo", 1, 2, 1))
	eventually(t, 30*time.Second, "intermediate 1-2 pending", func() error {
		cr := getCR(t, ns)
		if got := caStages(cr); got != "Root 1-0 Active,Intermediate 1-2 Pending,Intermediate 1-1 Active" {
			return fmt.Errorf("cas %s", got)
		}
		if got := signerStatus(cr); got != "1:ML-DSA-87:Pending,1:ML-DSA-65:Active" {
			return fmt.Errorf("signers %s", got)
		}
		return nil
	})
	next := decodeSigner(t, ns, 1, 2, 1)
	if !next.Root.Equal(old.Root) {
		t.Fatal("intermediate rotation changed the root")
	}
	if a, _ := pki.AlgorithmOf(next.Intermediate.PublicKey); a != pqcv1alpha1.MLDSA87 {
		t.Fatalf("intermediate 1-2 is %s, want ML-DSA-87", a)
	}
	time.Sleep(2 * time.Second)
	caSecret(t, ns, 1, 1)
	signerSecret(t, ns, 1, 1, 1)

	readyOn(t, ns, controller.TSASignerSecretName("demo", 1, 2, 1))
	eventually(t, 30*time.Second, "intermediate 1-1 retired", func() error {
		cr := getCR(t, ns)
		if got := caStages(cr); got != "Root 1-0 Active,Intermediate 1-2 Active,Intermediate 1-1 Retired" {
			return fmt.Errorf("cas %s", got)
		}
		if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-1-2", "demo-tsa-root-1", "demo-tsa-signer-1-2-1"}; !slices.Equal(got, want) {
			return fmt.Errorf("key Secrets %v", got)
		}
		return conditionIs(cr, pqcv1alpha1.ConditionTSACARotation, metav1.ConditionFalse, "NoRotation")
	})
	if getSecret(t, ns, controller.TSARootSecretName("demo", 1)).UID != root.UID {
		t.Fatal("root Secret replaced by an intermediate rotation")
	}
	published, err := publishedIntermediates(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{serial(old.Intermediate) + "-retired", serial(next.Intermediate)}; !slices.Equal(published, want) {
		t.Fatalf("trusted root lists %v, want %v", published, want)
	}
	if cr := getCR(t, ns); activeIntermediate(cr).SerialNumber != serial(next.Intermediate) || cr.Status.TSA.Signers[0].IssuerSerialNumber != serial(next.Intermediate) {
		t.Fatalf("status %+v", cr.Status.TSA)
	}
}

// Raising rootGeneration issues a new root, an intermediate under it and a
// signer, and once they are in use deletes every old private key, the old
// root's included. The old chain stays in the trusted root.
func TestTSARootRotation(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "rootrotate")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	readyOn(t, ns, controller.TSASignerSecretName("demo", 1, 1, 1))
	old := decodeSigner(t, ns, 1, 1, 1)

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.RootGeneration = 2 })
	rotationPending(t, ns, 2, 1, controller.TSASignerSecretName("demo", 2, 1, 1))
	eventually(t, 30*time.Second, "root 2 pending", func() error {
		if got := caStages(getCR(t, ns)); got != "Root 2-0 Pending,Intermediate 2-1 Pending,Root 1-0 Active,Intermediate 1-1 Active" {
			return fmt.Errorf("cas %s", got)
		}
		return nil
	})
	next := decodeSigner(t, ns, 2, 1, 1)
	if next.Root.Equal(old.Root) {
		t.Fatal("root rotation kept the root")
	}

	readyOn(t, ns, controller.TSASignerSecretName("demo", 2, 1, 1))
	eventually(t, 30*time.Second, "root 1 retired", func() error {
		if got := caStages(getCR(t, ns)); got != "Root 2-0 Active,Intermediate 2-1 Active,Root 1-0 Retired,Intermediate 1-1 Retired" {
			return fmt.Errorf("cas %s", got)
		}
		if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-2-1", "demo-tsa-root-2", "demo-tsa-signer-2-1-1"}; !slices.Equal(got, want) {
			return fmt.Errorf("key Secrets %v", got)
		}
		return nil
	})
	published, err := publishedIntermediates(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{serial(old.Intermediate) + "-retired", serial(next.Intermediate)}; !slices.Equal(published, want) {
		t.Fatalf("trusted root lists %v, want %v", published, want)
	}
}

// A root whose key Secret was deleted cannot issue an intermediate, so an
// intermediate rotation is refused until a root rotation, which retires
// the old CA.
func TestDeletedRootKeyNeedsRootRotation(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "rootkey")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	readyOn(t, ns, controller.TSASignerSecretName("demo", 1, 1, 1))
	old := decodeSigner(t, ns, 1, 1, 1)
	root := getSecret(t, ns, controller.TSARootSecretName("demo", 1))
	if err := k8s.Delete(ctx, root); err != nil {
		t.Fatal(err)
	}

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.IntermediateGeneration = 2 })
	eventually(t, 30*time.Second, "RootKeyUnavailable", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "RootKeyUnavailable"); err != nil {
			return err
		}
		if c := meta.FindStatusCondition(cr.Status.Conditions, pqcv1alpha1.ConditionReady); !strings.Contains(c.Message, "raise spec.tsa.signing.rootGeneration to 2") {
			return fmt.Errorf("message %q", c.Message)
		}
		return nil
	})
	if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-1-1", "demo-tsa-signer-1-1-1"}; !slices.Equal(got, want) {
		t.Fatalf("key Secrets %v, want %v", got, want)
	}

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.RootGeneration = 2 })
	rotationPending(t, ns, 2, 2, controller.TSASignerSecretName("demo", 2, 2, 1))
	readyOn(t, ns, controller.TSASignerSecretName("demo", 2, 2, 1))
	eventually(t, 30*time.Second, "CA 1-1 retired", func() error {
		if got, want := keySecrets(t, ns), []string{"demo-tsa-intermediate-2-2", "demo-tsa-root-2", "demo-tsa-signer-2-2-1"}; !slices.Equal(got, want) {
			return fmt.Errorf("key Secrets %v", got)
		}
		return nil
	})
	published, err := publishedIntermediates(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(published) != 2 || published[0] != serial(old.Intermediate)+"-retired" {
		t.Fatalf("trusted root lists %v; intermediate 1-1 must stay, retired", published)
	}
}

// A raise while a CA rotation rolls out waits, with one event, and starts
// once the rotation finishes.
func TestCARotationHeld(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "held")
	if err := k8s.Create(ctx, newInstance(ns)); err != nil {
		t.Fatal(err)
	}
	readyOn(t, ns, controller.TSASignerSecretName("demo", 1, 1, 1))
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.IntermediateGeneration = 2 })
	rotationPending(t, ns, 1, 2, controller.TSASignerSecretName("demo", 1, 2, 1))

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.IntermediateGeneration = 3 })
	eventually(t, 30*time.Second, "RotationHeld", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionTSACARotation, metav1.ConditionTrue, "RotationHeld")
	})
	time.Sleep(2 * time.Second)
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAIntermediateSecretName("demo", 1, 3)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("intermediate 1-3 issued during the rotation to 1-2: %v", err)
	}
	eventually(t, 30*time.Second, "RotationHeld event", func() error {
		var list eventsv1.EventList
		if err := k8s.List(ctx, &list, client.InNamespace(ns)); err != nil {
			return err
		}
		n := 0
		for _, e := range list.Items {
			if e.Reason == "RotationHeld" {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("%d RotationHeld events", n)
		}
		return nil
	})

	markAvailable(t, ns)
	rotationPending(t, ns, 1, 3, controller.TSASignerSecretName("demo", 1, 3, 1))
	readyOn(t, ns, controller.TSASignerSecretName("demo", 1, 3, 1))
	eventually(t, 30*time.Second, "both rotations done", func() error {
		if got := caStages(getCR(t, ns)); got != "Root 1-0 Active,Intermediate 1-3 Active,Intermediate 1-2 Retired,Intermediate 1-1 Retired" {
			return fmt.Errorf("cas %s", got)
		}
		return nil
	})
}

// A weaker CA needs an acceptance naming its rotation; that acceptance also
// covers the signer the rotation issues.
func TestWeakerCANeedsAcceptance(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "weakerca")
	cr := newInstance(ns)
	cr.Spec.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA87
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	readyOn(t, ns, controller.TSASignerSecretName("demo", 1, 1, 1))
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) {
		s.TSA.Signing.Algorithm = pqcv1alpha1.MLDSA44
		s.TSA.Signing.AcceptWeakerAlgorithm = &pqcv1alpha1.WeakerAlgorithmAcceptance{Algorithm: pqcv1alpha1.MLDSA44, IntermediateGeneration: 2}
	})
	// Admission only checks the acceptance when the algorithm changes.
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.AcceptWeakerAlgorithm.IntermediateGeneration = 3 })
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.IntermediateGeneration = 2 })
	eventually(t, 30*time.Second, "blocked", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "WeakerAlgorithmNotAccepted")
	})
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAIntermediateSecretName("demo", 1, 2)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("weaker intermediate created without acceptance: %v", err)
	}

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.AcceptWeakerAlgorithm.IntermediateGeneration = 2 })
	rotationPending(t, ns, 1, 2, controller.TSASignerSecretName("demo", 1, 2, 1))
	chain := decodeSigner(t, ns, 1, 2, 1)
	for _, c := range []*x509.Certificate{chain.Intermediate, chain.Leaf} {
		if a, _ := pki.AlgorithmOf(c.PublicKey); a != pqcv1alpha1.MLDSA44 {
			t.Fatalf("%s is %s, want ML-DSA-44", c.Subject.CommonName, a)
		}
	}
}
