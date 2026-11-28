package controller

import (
	"bytes"
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
	"sigs.k8s.io/controller-runtime/pkg/client"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"

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
	d := renderTSA(t, testInstance(), TSASignerSecretName("demo", 1, 1, 3), testSigner, "")
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, ca := range []string{TSAIntermediateSecretName("demo", 1, 1), TSARootSecretName("demo", 1), pki.IntermediateKeyPEM, pki.RootKeyPEM} {
		if strings.Contains(string(raw), ca) {
			t.Fatalf("pod spec references %s", ca)
		}
	}
	var secrets []string
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Secret != nil {
			secrets = append(secrets, *v.Secret.SecretName)
		}
	}
	if !slices.Equal(secrets, []string{"demo-tsa-signer-1-1-3"}) {
		t.Fatalf("secret volumes %v, want [demo-tsa-signer-1-1-3]", secrets)
	}
}

func TestKeyToInstance(t *testing.T) {
	secret := func(name string, labels map[string]string) *corev1.Secret {
		return &corev1.Secret{Namespace: "ns", Name: name, Labels: labels}
	}
	cr := testInstance()
	signer := tsaCA.genLabels(cr, RoleTSASigner, caGen{1, 1})
	signer[LabelKeyGeneration] = "4"
	for name, tc := range map[string]struct {
		obj  client.Object
		want int
	}{
		"signer":       {secret("demo-tsa-signer-1-1-4", signer), 1},
		"root":         {secret("demo-tsa-root-1", tsaCA.labels(cr, RoleTSARoot)), 1},
		"intermediate": {secret("demo-tsa-intermediate-1-1", tsaCA.genLabels(cr, RoleTSAIntermediate, caGen{1, 1})), 1},
		"chain":        {&corev1.ConfigMap{Namespace: "ns", Name: "demo-tsa-chain-1-1", Labels: tsaCA.genLabels(cr, RoleTSAChain, caGen{1, 1})}, 1},
		"trusted root": {&corev1.ConfigMap{Namespace: "ns", Name: "demo-trusted-root", Labels: map[string]string{LabelName: "trusted-root", LabelInstance: "demo"}}, 1},
		"unrelated":    {secret("other", map[string]string{LabelInstance: "demo"}), 0},
	} {
		got := keyToInstance(context.Background(), tc.obj)
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

// testCA is one root and intermediate, the root issued at rootIssued and
// the intermediate at intIssued; withRootKey keeps the root's key Secret,
// as instances created since CA rotation do.
func testCA(t *testing.T, gen caGen, rootIssued, intIssued time.Time, withRootKey bool) *caState {
	t.Helper()
	root, err := pki.NewRoot(pqcv1alpha1.MLDSA44, "test root", rootIssued)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := root.IssueIntermediate(pqcv1alpha1.MLDSA44, "test intermediate", pki.TSAIntermediateEKU, intIssued)
	if err != nil {
		t.Fatal(err)
	}
	st := &caState{cas: []caKey{{gen: gen, secret: &corev1.Secret{}, ca: ca}}, want: gen}
	if withRootKey {
		st.roots = []rootKey{{gen: gen.root, secret: &corev1.Secret{}, root: root}}
	}
	st.target = &st.cas[0]
	return st
}

func TestCheckExpiry(t *testing.T) {
	const year = 365 * 24 * time.Hour
	const month = 30 * 24 * time.Hour
	now := time.Now()
	fresh := testCA(t, caGen{1, 1}, now, now, true)
	expiringInt := testCA(t, caGen{1, 1}, now, now.Add(-5*year+month), true)
	// Issued with less than an intermediate's lifetime left on the root,
	// so it ends with the root.
	endsWithRoot := testCA(t, caGen{1, 1}, now.Add(-10*year+month), now.Add(-4*year), true)
	noRootKey := testCA(t, caGen{1, 1}, now, now.Add(-5*year+month), false)
	rotating := testCA(t, caGen{1, 2}, now, now, true)
	rotating.cas = append(rotating.cas, expiringInt.cas[0])
	rotating.target = &rotating.cas[0]

	signer := func(st *caState, k int, issued time.Time) *tsaSigner {
		leaf, err := st.cas[k].ca.IssueLeaf(pqcv1alpha1.MLDSA44, "test", issued)
		if err != nil {
			t.Fatal(err)
		}
		return &tsaSigner{generation: 2, ca: st.cas[k].gen, chain: leaf}
	}
	older := func(s *tsaSigner) []tsaSigner {
		o := *s
		o.generation = 1
		return []tsaSigner{o}
	}
	expiringSigner := signer(fresh, 0, now.Add(-year+month))
	for name, tc := range map[string]struct {
		st     *caState
		signer *tsaSigner
		older  []tsaSigner
		status metav1.ConditionStatus
		reason string
		says   string
	}{
		"fresh":            {fresh, signer(fresh, 0, now), nil, metav1.ConditionFalse, "NotExpiring", ""},
		"signer":           {fresh, expiringSigner, nil, metav1.ConditionTrue, "SignerExpiring", "raise spec.tsa.signing.signerGeneration"},
		"intermediate":     {expiringInt, signer(expiringInt, 0, now), nil, metav1.ConditionTrue, "CAExpiring", "intermediate CA 1-1 certificate expires at"},
		"intermediate fix": {expiringInt, signer(expiringInt, 0, now), nil, metav1.ConditionTrue, "CAExpiring", "raise spec.tsa.signing.intermediateGeneration"},
		"ends with root":   {endsWithRoot, signer(endsWithRoot, 0, now), nil, metav1.ConditionTrue, "CAExpiring", "raise spec.tsa.signing.rootGeneration"},
		"no root key":      {noRootKey, signer(noRootKey, 0, now), nil, metav1.ConditionTrue, "CAExpiring", "raise spec.tsa.signing.rootGeneration"},
		"signer at CA":     {expiringInt, signer(expiringInt, 0, now.Add(-year+month)), nil, metav1.ConditionTrue, "CAExpiring", "intermediate CA"},
		"outside window":   {fresh, signer(fresh, 0, now.Add(-year/2)), nil, metav1.ConditionFalse, "NotExpiring", ""},
		"older serving":    {fresh, signer(fresh, 0, now), older(expiringSigner), metav1.ConditionTrue, "SignerExpiring", "generation 1 of intermediate 1-1 (in use until generation 2 rolls out)"},
		"old CA rotating":  {rotating, signer(rotating, 0, now), nil, metav1.ConditionTrue, "CAExpiring", "finish that rollout"},
	} {
		events := &recordedEvents{}
		r := &SecureSignPQCReconciler{Settings: tuning.NewLive(tuning.Defaults()), Recorder: events}
		cr := testInstance()
		soon := now.Add(r.Settings.Load().ExpiryWarning)
		for range 2 {
			r.checkExpiry(cr, tsaExpiryChecks(tc.st, tc.signer, tc.older, soon), soon)
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
	st := testCA(t, caGen{1, 1}, now, now, true)
	records := []chainRecord{{gen: st.target.gen, chain: st.target.ca}}
	signer := func(gen int32) tsaSigner {
		leaf, err := st.target.ca.IssueLeaf(pqcv1alpha1.MLDSA65, "test", now)
		if err != nil {
			t.Fatal(err)
		}
		return tsaSigner{generation: gen, ca: st.target.gen, chain: leaf}
	}
	one, two, three := signer(1), signer(2), signer(3)
	cr := testInstance()

	// Pass 1: generation 2 is in use, generation 1 is marked retired, and
	// its delete fails.
	setTSAKeys(cr, st, records, &two, nil, true, []tsaSigner{one})
	// Pass 2: generation 3 is pending, so generation 2 and the undeleted
	// generation 1 are listed from their Secrets.
	setTSAKeys(cr, st, records, &three, []tsaSigner{two, one}, false, nil)

	got := make([]string, 0, len(cr.Status.TSA.Signers))
	for _, k := range cr.Status.TSA.Signers {
		got = append(got, fmt.Sprintf("%d:%s", k.Generation, k.Stage))
	}
	if want := []string{"3:Pending", "2:Active", "1:Active"}; !slices.Equal(got, want) {
		t.Fatalf("signers %v, want %v", got, want)
	}
	if k := cr.Status.TSA.Signers[0]; k.IssuerSerialNumber != st.target.ca.Intermediate.SerialNumber.Text(16) {
		t.Fatalf("signer issuer %s, want the intermediate", k.IssuerSerialNumber)
	}
}

// Status lists each root before its intermediates, newest first, and a
// root is retired only once every intermediate under it is.
func TestCAStatus(t *testing.T) {
	now := time.Now()
	retired := now.Add(-time.Hour)
	old := testCA(t, caGen{1, 1}, now, now, true)
	mid := testCA(t, caGen{2, 1}, now, now, true)
	newer, err := mid.roots[0].root.IssueIntermediate(pqcv1alpha1.MLDSA65, "test intermediate", pki.TSAIntermediateEKU, now)
	if err != nil {
		t.Fatal(err)
	}
	records := []chainRecord{
		{gen: caGen{2, 2}, chain: newer},
		{gen: caGen{2, 1}, chain: mid.target.ca, retiredAt: &retired},
		{gen: caGen{1, 1}, chain: old.target.ca, retiredAt: &retired},
	}
	describe := func(list []pqcv1alpha1.CAStatus) []string {
		out := make([]string, 0, len(list))
		for _, s := range list {
			out = append(out, s.String())
		}
		return out
	}
	got := describe(caStatus(records, caGen{2, 2}, true))
	want := []string{"Root 2-0 Active", "Intermediate 2-2 Pending", "Intermediate 2-1 Retired", "Root 1-0 Retired", "Intermediate 1-1 Retired"}
	if !slices.Equal(got, want) {
		t.Fatalf("cas %v, want %v", got, want)
	}
	if got := describe(caStatus(records[:1], caGen{2, 2}, true)); !slices.Equal(got, []string{"Root 2-0 Pending", "Intermediate 2-2 Pending"}) {
		t.Fatalf("cas %v: a root whose only intermediate is pending is pending", got)
	}
	list := caStatus(records, caGen{2, 2}, false)
	if list[1].IssuerSerialNumber != list[0].SerialNumber || list[0].IssuerSerialNumber != "" || list[3].RetiredAt == nil {
		t.Fatalf("cas %+v", list)
	}
}

// The trusted root lists every chain, oldest first, without a leaf, and
// gives a retired chain its validity end.
func TestTrustedRoot(t *testing.T) {
	now := time.Now()
	retired := now.Add(-time.Hour).Truncate(time.Second)
	a := testCA(t, caGen{1, 1}, now, now, true)
	b := testCA(t, caGen{2, 1}, now, now, true)
	raw, err := trustedRoot(testInstance(), []rootPart{componentRecords{tsaCA, []chainRecord{
		{gen: caGen{2, 1}, chain: b.target.ca},
		{gen: caGen{1, 1}, chain: a.target.ca, retiredAt: &retired},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var tr prototrustroot.TrustedRoot
	if err := protojson.Unmarshal(raw, &tr); err != nil {
		t.Fatal(err)
	}
	tsas := tr.GetTimestampAuthorities()
	if tr.GetMediaType() != trustedRootMediaType || len(tsas) != 2 {
		t.Fatalf("trusted root %v", &tr)
	}
	first := tsas[0].GetCertChain().GetCertificates()
	if len(first) != 2 || !bytes.Equal(first[0].GetRawBytes(), a.target.ca.Intermediate.Raw) || !bytes.Equal(first[1].GetRawBytes(), a.target.ca.Root.Raw) {
		t.Fatal("first entry is not the old intermediate and root")
	}
	if end := tsas[0].GetValidFor().GetEnd(); end == nil || !end.AsTime().Equal(retired) {
		t.Fatalf("retired entry ends %v, want %s", end, retired)
	}
	if tsas[1].GetValidFor().End != nil || tsas[1].GetUri() != "http://demo-tsa.ns.svc:3000/api/v1/timestamp" {
		t.Fatalf("current entry %v", tsas[1])
	}
}
