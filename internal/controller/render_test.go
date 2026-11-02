package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	"k8s.io/utils/ptr"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
)

func testInstance() *pqcv1alpha1.SecureSignPQC {
	return &pqcv1alpha1.SecureSignPQC{
		Namespace: "ns", Name: "demo", UID: "uid-1",
		Spec: pqcv1alpha1.SecureSignPQCSpec{
			Version: "2.0",
			TSA: pqcv1alpha1.TSASpec{
				Replicas: ptr.To[int32](2),
				Signing:  pqcv1alpha1.SigningSpec{Algorithm: pqcv1alpha1.MLDSA65},
			},
		},
	}
}

var testSigner = map[string][]byte{pki.KeyPEM: []byte("k"), pki.ChainPEM: []byte("c")}

func renderTSA(t *testing.T, cr *pqcv1alpha1.SecureSignPQC, signerSecret string, signer map[string][]byte, fips string) *appsv1ac.DeploymentApplyConfiguration {
	t.Helper()
	d, err := tsaDeployment(cr, "img@sha256:1", signerSecret, signer, fips)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// OpenShift assigns each namespace its own UID range and rejects pods that
// pick a UID outside it, so no rendered workload may name a UID, GID or
// fsGroup.
func TestTSADeploymentLeavesUIDToPlatform(t *testing.T) {
	raw, err := json.Marshal(renderTSA(t, testInstance(), "demo-tsa-signer-1", testSigner, ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"runAsUser", "runAsGroup", "fsGroup", "supplementalGroups"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Errorf("rendered Deployment sets %s", field)
		}
	}
}

func TestTSADeploymentRestricted(t *testing.T) {
	d := renderTSA(t, testInstance(), "demo-tsa-signer-1", testSigner, "")
	pod := d.Spec.Template.Spec
	if !ptr.Deref(pod.SecurityContext.RunAsNonRoot, false) {
		t.Error("pod runAsNonRoot not set")
	}
	if *pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("pod seccomp not RuntimeDefault")
	}
	if ptr.Deref(pod.AutomountServiceAccountToken, true) {
		t.Error("service account token mounted")
	}
	c := pod.Containers[0]
	sc := c.SecurityContext
	if ptr.Deref(sc.AllowPrivilegeEscalation, true) || !ptr.Deref(sc.ReadOnlyRootFilesystem, false) {
		t.Error("container allows privilege escalation or writable root")
	}
	if !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(sc.Capabilities.Add) != 0 {
		t.Errorf("capabilities %+v, want drop ALL only", sc.Capabilities)
	}
	if *c.Image != "img@sha256:1" {
		t.Errorf("image %s", *c.Image)
	}
	if *d.Spec.Replicas != 2 {
		t.Errorf("replicas %d", *d.Spec.Replicas)
	}
	for _, want := range []string{"--timestamp-signer=file", "--timestamp-signer-hash=sha512", "--experimental-enable-pqc"} {
		if !slices.Contains(c.Args, want) {
			t.Errorf("args missing %s", want)
		}
	}
}

func TestFIPSMode(t *testing.T) {
	for name, tc := range map[string]struct {
		annotations map[string]string
		want        string
	}{
		"default":             {nil, "fips140=auto"},
		"unrelated annotated": {map[string]string{"other": "x"}, "fips140=auto"},
		"auto":                {map[string]string{pqcv1alpha1.FIPSAnnotation: "auto"}, "fips140=auto"},
		"on":                  {map[string]string{pqcv1alpha1.FIPSAnnotation: "on"}, "fips140=on"},
		"only":                {map[string]string{pqcv1alpha1.FIPSAnnotation: "only"}, "fips140=only"},
		"off":                 {map[string]string{pqcv1alpha1.FIPSAnnotation: "off"}, ""},
		"empty":               {map[string]string{pqcv1alpha1.FIPSAnnotation: ""}, ""},
		"full GODEBUG":        {map[string]string{pqcv1alpha1.FIPSAnnotation: "fips140=on"}, ""},
	} {
		cr := testInstance()
		cr.Annotations = tc.annotations
		fips, err := fipsMode(cr)
		if tc.want == "" {
			if b, ok := errors.AsType[*blockedError](err); !ok || b.reason != "InvalidFIPSMode" {
				t.Errorf("%s: got %v, want InvalidFIPSMode", name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		d := renderTSA(t, cr, "demo-tsa-signer-1", testSigner, fips)
		var got []string
		for _, e := range d.Spec.Template.Spec.Containers[0].Env {
			if *e.Name == "GODEBUG" {
				got = append(got, *e.Value)
			}
		}
		if !slices.Equal(got, []string{tc.want}) {
			t.Errorf("%s: GODEBUG %v, want %s", name, got, tc.want)
		}
	}
}

// Unset pod options keep the operator's defaults; set ones reach the pod
// spec, and resources replace the defaults as a whole.
func TestTSAPodOptions(t *testing.T) {
	d := renderTSA(t, testInstance(), "demo-tsa-signer-1", testSigner, "auto")
	pod := d.Spec.Template.Spec
	res := pod.Containers[0].Resources
	if !maps.Equal(*res.Requests, tsaResources.Requests) || !maps.Equal(*res.Limits, tsaResources.Limits) {
		t.Errorf("default resources %v %v, want %v", *res.Requests, *res.Limits, tsaResources)
	}
	if pod.NodeSelector != nil || pod.Tolerations != nil || pod.Affinity != nil || pod.TopologySpreadConstraints != nil || pod.PriorityClassName != nil {
		t.Errorf("unset scheduling fields rendered: %+v", pod)
	}

	cr := testInstance()
	cr.Spec.TSA.PodOptions = pqcv1alpha1.PodOptions{
		Resources: &pqcv1alpha1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
		},
		NodeSelector: map[string]string{"pool": "tsa"},
		Tolerations:  []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "tsa", Effect: corev1.TaintEffectNoSchedule}},
		Affinity: &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
				Weight:          100,
				PodAffinityTerm: corev1.PodAffinityTerm{TopologyKey: "kubernetes.io/hostname"},
			}},
		}},
		TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "topology.kubernetes.io/zone", WhenUnsatisfiable: corev1.ScheduleAnyway}},
		PriorityClassName:         "tsa-critical",
	}
	pod = renderTSA(t, cr, "demo-tsa-signer-1", testSigner, "auto").Spec.Template.Spec
	res = pod.Containers[0].Resources
	if !maps.Equal(*res.Requests, cr.Spec.TSA.Resources.Requests) || !maps.Equal(*res.Limits, cr.Spec.TSA.Resources.Limits) {
		t.Errorf("resources %v %v, want only the instance's", *res.Requests, *res.Limits)
	}
	if !maps.Equal(pod.NodeSelector, cr.Spec.TSA.NodeSelector) {
		t.Errorf("nodeSelector %v", pod.NodeSelector)
	}
	if len(pod.Tolerations) != 1 || *pod.Tolerations[0].Key != "dedicated" || *pod.Tolerations[0].Effect != corev1.TaintEffectNoSchedule {
		t.Errorf("tolerations %+v", pod.Tolerations)
	}
	if a := pod.Affinity; a == nil || a.PodAntiAffinity == nil || len(a.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 ||
		*a.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0].PodAffinityTerm.TopologyKey != "kubernetes.io/hostname" {
		t.Errorf("affinity %+v", pod.Affinity)
	}
	if len(pod.TopologySpreadConstraints) != 1 || *pod.TopologySpreadConstraints[0].TopologyKey != "topology.kubernetes.io/zone" {
		t.Errorf("topologySpreadConstraints %+v", pod.TopologySpreadConstraints)
	}
	if ptr.Deref(pod.PriorityClassName, "") != "tsa-critical" {
		t.Errorf("priorityClassName %v", pod.PriorityClassName)
	}
	// What the pods run and mount is unchanged.
	if len(pod.Volumes) != 2 || !ptr.Deref(pod.SecurityContext.RunAsNonRoot, false) || ptr.Deref(pod.AutomountServiceAccountToken, true) {
		t.Errorf("pod options changed the pod's volumes or security: %+v", pod)
	}
}

func TestTSADeploymentRollsOnSignerChange(t *testing.T) {
	a := renderTSA(t, testInstance(), "demo-tsa-signer-1", testSigner, "")
	b := renderTSA(t, testInstance(), "demo-tsa-signer-2", map[string][]byte{pki.KeyPEM: []byte("k2"), pki.ChainPEM: []byte("c")}, "")
	if a.Spec.Template.Annotations[TSASignerHashAnnotation] == b.Spec.Template.Annotations[TSASignerHashAnnotation] {
		t.Fatal("signer change does not change the pod template")
	}
}

// The pods mount the current signer and nothing else: the intermediate CA
// key stays out of every pod.
func TestTSADeploymentMountsOnlyTheSigner(t *testing.T) {
	d := renderTSA(t, testInstance(), TSASignerSecretName("demo", 3), testSigner, "")
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), TSACASecretName("demo")) || strings.Contains(string(raw), pki.IntermediateKeyPEM) {
		t.Fatal("pod spec references the TSA CA Secret")
	}
	var secrets []string
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Secret != nil {
			secrets = append(secrets, *v.Secret.SecretName)
		}
	}
	if !slices.Equal(secrets, []string{"demo-tsa-signer-3"}) {
		t.Fatalf("secret volumes %v, want [demo-tsa-signer-3]", secrets)
	}
}

func TestSignerToInstance(t *testing.T) {
	secret := func(name string, labels map[string]string) *corev1.Secret {
		return &corev1.Secret{Namespace: "ns", Name: name, Labels: labels}
	}
	cr := testInstance()
	signer := keySecretLabels(cr, RoleTSASigner)
	signer[LabelKeyGeneration] = "4"
	for name, tc := range map[string]struct {
		obj  *corev1.Secret
		want int
	}{
		"signer":    {secret("demo-tsa-signer-4", signer), 1},
		"ca":        {secret("demo-tsa-ca", keySecretLabels(cr, RoleTSACA)), 1},
		"unrelated": {secret("other", map[string]string{LabelInstance: "demo"}), 0},
	} {
		got := signerToInstance(context.Background(), tc.obj)
		if len(got) != tc.want || (tc.want == 1 && got[0].Name != "demo") {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestTSAService(t *testing.T) {
	s := tsaService(testInstance())
	if len(s.Spec.Ports) != 1 || *s.Spec.Ports[0].Port != tsaPort {
		t.Fatalf("ports %+v", s.Spec.Ports)
	}
	if got := TSAURL(testInstance()); got != "http://demo-tsa.ns.svc:3000" {
		t.Fatalf("url %s", got)
	}
}

func TestCheckExpiry(t *testing.T) {
	const year = 365 * 24 * time.Hour
	now := time.Now()
	ca, err := pki.NewTSACA(pqcv1alpha1.MLDSA44, "test", now.Add(-15*year+30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	freshCA, err := pki.NewTSACA(pqcv1alpha1.MLDSA44, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(ca *pki.TSACA, issued time.Time) *tsaSigner {
		leaf, err := ca.IssueLeaf(pqcv1alpha1.MLDSA44, "test", issued)
		if err != nil {
			t.Fatal(err)
		}
		return &tsaSigner{generation: 2, chain: leaf}
	}
	older := func(s *tsaSigner) []tsaSigner { return []tsaSigner{{generation: 1, chain: s.chain}} }
	expiringSigner := signer(freshCA, now.Add(-10*year+30*24*time.Hour))
	for name, tc := range map[string]struct {
		ca     *pki.TSACA
		signer *tsaSigner
		older  []tsaSigner
		status metav1.ConditionStatus
		reason string
		says   string
	}{
		"fresh":          {freshCA, signer(freshCA, now), nil, metav1.ConditionFalse, "NotExpiring", ""},
		"signer":         {freshCA, expiringSigner, nil, metav1.ConditionTrue, "SignerExpiring", "raise spec.tsa.signing.signerGeneration"},
		"intermediate":   {ca, signer(ca, now), nil, metav1.ConditionTrue, "CAExpiring", "intermediate CA"},
		"signer at CA":   {ca, signer(ca, now.Add(-10*year+30*24*time.Hour)), nil, metav1.ConditionTrue, "CAExpiring", "intermediate CA"},
		"outside window": {freshCA, signer(freshCA, now.Add(-9*year)), nil, metav1.ConditionFalse, "NotExpiring", ""},
		"older serving":  {freshCA, signer(freshCA, now), older(expiringSigner), metav1.ConditionTrue, "SignerExpiring", "generation 1 (in use until generation 2 rolls out)"},
	} {
		events := &recordedEvents{}
		r := &SecureSignPQCReconciler{Settings: tuning.NewLive(tuning.Defaults()), Recorder: events}
		cr := testInstance()
		for range 2 {
			r.checkExpiry(cr, tc.ca, tc.signer, tc.older, now)
		}
		c := meta.FindStatusCondition(cr.Status.Conditions, pqcv1alpha1.ConditionCertificatesExpiring)
		if c == nil || c.Status != tc.status || c.Reason != tc.reason || !strings.Contains(c.Message, tc.says) {
			t.Errorf("%s: condition %+v, want %s/%s saying %q", name, c, tc.status, tc.reason, tc.says)
			continue
		}
		if want := map[bool]int{true: 1, false: 0}[tc.status == metav1.ConditionTrue]; len(events.reasons) != want {
			t.Errorf("%s: %d events %v, want %d", name, len(events.reasons), events.reasons, want)
		}
	}
}

type recordedEvents struct{ reasons []string }

func (e *recordedEvents) Eventf(_ runtime.Object, _ runtime.Object, _, reason, _, _ string, _ ...any) {
	e.reasons = append(e.reasons, reason)
}

// A key marked retired whose delete failed is listed again from its Secret
// on the next pass; status must report it once, from the Secret.
func TestSetTSAKeysListsEachGenerationOnce(t *testing.T) {
	now := time.Now()
	ca, err := pki.NewTSACA(pqcv1alpha1.MLDSA65, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(gen int32) tsaSigner {
		leaf, err := ca.IssueLeaf(pqcv1alpha1.MLDSA65, "test", now)
		if err != nil {
			t.Fatal(err)
		}
		return tsaSigner{generation: gen, chain: leaf}
	}
	one, two, three := signer(1), signer(2), signer(3)
	cr := testInstance()

	// Pass 1: generation 2 is in use, generation 1 is marked retired, and
	// its delete fails.
	setTSAKeys(cr, ca, &two, nil, true, []tsaSigner{one})
	// Pass 2: generation 3 is pending, so generation 2 and the undeleted
	// generation 1 are listed from their Secrets.
	setTSAKeys(cr, ca, &three, []tsaSigner{two, one}, false, nil)

	got := make([]string, 0, len(cr.Status.TSA.Signers))
	for _, k := range cr.Status.TSA.Signers {
		got = append(got, fmt.Sprintf("%d:%s", k.Generation, k.Stage))
	}
	if want := []string{"3:Pending", "2:Active", "1:Active"}; !slices.Equal(got, want) {
		t.Fatalf("signers %v, want %v", got, want)
	}
}
