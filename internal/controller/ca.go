package controller

import (
	"cmp"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strconv"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
)

// Labels on CA key Secrets, signer Secrets and chain records.
const (
	LabelRootGeneration         = "pqc.rhtas.redhat.com/root-generation"
	LabelIntermediateGeneration = "pqc.rhtas.redhat.com/intermediate-generation"
)

// caGen names an intermediate CA by its root and intermediate generations.
type caGen struct{ root, intermediate int32 }

func (g caGen) String() string { return fmt.Sprintf("%d-%d", g.root, g.intermediate) }

func (g caGen) compare(o caGen) int {
	if c := cmp.Compare(g.root, o.root); c != 0 {
		return c
	}
	return cmp.Compare(g.intermediate, o.intermediate)
}

// caComponent is a component whose root and intermediate CAs the operator
// generates.
type caComponent struct {
	// name is the component's LabelName and the part of its Secret names
	// after the instance name.
	name      string
	component string
	// title names the component in messages and certificate subjects.
	title string
	// path is the field path of the component's SigningSpec.
	path             string
	eku              []x509.ExtKeyUsage
	roleRoot         string
	roleIntermediate string
	roleChain        string
	// rotationCondition is the condition type that is True while one of
	// the component's CA rotations rolls out.
	rotationCondition string
	// authorities is the list in a trusted root that holds the component's
	// CAs, and url the endpoint its entries name.
	authorities func(*prototrustroot.TrustedRoot) *[]*prototrustroot.CertificateAuthority
	url         func(*pqcv1alpha1.SecureSignPQC) string
}

// caComponents are the components whose CAs the operator generates.
var caComponents = []caComponent{tsaCA}

// ownsRole reports whether role is one of c's CA Secrets or chain records.
func (c caComponent) ownsRole(role string) bool {
	return role == c.roleRoot || role == c.roleIntermediate || role == c.roleChain
}

func (c caComponent) rootSecretName(instance string, root int32) string {
	return fmt.Sprintf("%s-%s-root-%d", instance, c.name, root)
}

func (c caComponent) intermediateSecretName(instance string, g caGen) string {
	return fmt.Sprintf("%s-%s-intermediate-%d-%d", instance, c.name, g.root, g.intermediate)
}

func (c caComponent) chainName(instance string, g caGen) string {
	return fmt.Sprintf("%s-%s-chain-%d-%d", instance, c.name, g.root, g.intermediate)
}

func (c caComponent) labels(cr *pqcv1alpha1.SecureSignPQC, role string) map[string]string {
	return map[string]string{
		LabelName:      c.name,
		LabelInstance:  cr.Name,
		LabelComponent: c.component,
		LabelManagedBy: ManagedBy,
		LabelKeyRole:   role,
	}
}

func (c caComponent) genLabels(cr *pqcv1alpha1.SecureSignPQC, role string, g caGen) map[string]string {
	l := c.labels(cr, role)
	l[LabelRootGeneration] = strconv.Itoa(int(g.root))
	l[LabelIntermediateGeneration] = strconv.Itoa(int(g.intermediate))
	return l
}

type rootKey struct {
	gen    int32
	secret *corev1.Secret
	root   *pki.Root
}

type caKey struct {
	gen    caGen
	secret *corev1.Secret
	ca     *pki.CA
}

// caState is a component's CA keys and the intermediate it issues from.
type caState struct {
	// roots and cas are newest first.
	roots  []rootKey
	cas    []caKey
	target *caKey
	// held is set when the spec asks for a CA newer than target, which
	// waits for target's rotation to finish.
	held bool
	want caGen
}

// rotating is true while more than one intermediate has its key: the newest
// rolls out and the others retire once nothing uses them.
func (s *caState) rotating() bool { return len(s.cas) > 1 }

// rootRotation is true when target's rotation brought a new root.
func (s *caState) rootRotation() bool {
	return s.rotating() && s.target.gen.root > s.cas[1].gen.root
}

func (s *caState) find(g caGen) *caKey {
	for i := range s.cas {
		if s.cas[i].gen == g {
			return &s.cas[i]
		}
	}
	return nil
}

func (s *caState) rootKey(gen int32) *rootKey {
	for i := range s.roots {
		if s.roots[i].gen == gen {
			return &s.roots[i]
		}
	}
	return nil
}

func labelGeneration(s client.Object, label string) (int32, error) {
	g, err := strconv.ParseInt(s.GetLabels()[label], 10, 32)
	if err != nil || g < 1 {
		return 0, fmt.Errorf("label %s=%q is not a positive generation", label, s.GetLabels()[label])
	}
	return int32(g), nil
}

func labelCAGen(s client.Object) (caGen, error) {
	r, err := labelGeneration(s, LabelRootGeneration)
	if err != nil {
		return caGen{}, err
	}
	i, err := labelGeneration(s, LabelIntermediateGeneration)
	if err != nil {
		return caGen{}, err
	}
	return caGen{r, i}, nil
}

// listCAs reads c's root and intermediate Secrets from the API server.
func (r *SecureSignPQCReconciler) listCAs(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent) (*caState, error) {
	var list corev1.SecretList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(cr.Namespace), client.MatchingLabels{LabelInstance: cr.Name}); err != nil {
		return nil, err
	}
	st := &caState{}
	for i := range list.Items {
		s := &list.Items[i]
		switch s.Labels[LabelKeyRole] {
		case c.roleRoot:
			g, err := labelGeneration(s, LabelRootGeneration)
			if err != nil {
				return nil, invalidSecret(s.Name, err)
			}
			root, err := pki.DecodeRoot(s.Data)
			if err != nil {
				return nil, invalidSecret(s.Name, err)
			}
			st.roots = append(st.roots, rootKey{gen: g, secret: s, root: root})
		case c.roleIntermediate:
			g, err := labelCAGen(s)
			if err != nil {
				return nil, invalidSecret(s.Name, err)
			}
			ca, err := pki.DecodeCA(s.Data)
			if err != nil {
				return nil, invalidSecret(s.Name, err)
			}
			if st.find(g) != nil {
				return nil, invalidSecret(s.Name, fmt.Errorf("a second %s CA Secret for generation %s", c.title, g))
			}
			st.cas = append(st.cas, caKey{gen: g, secret: s, ca: ca})
		}
	}
	slices.SortFunc(st.roots, func(a, b rootKey) int { return cmp.Compare(b.gen, a.gen) })
	slices.SortFunc(st.cas, func(a, b caKey) int { return b.gen.compare(a.gen) })
	for _, k := range st.cas {
		if root := st.rootKey(k.gen.root); root != nil && !root.root.Cert.Equal(k.ca.Root) {
			return nil, invalidSecret(k.secret.Name, fmt.Errorf("not issued by root Secret %s", root.secret.Name))
		}
	}
	return st, nil
}

// ensureCA returns c's CA state with target set to the intermediate that
// issues new keys, creating the root and intermediate the spec asks for
// unless another rotation is still rolling out.
func (r *SecureSignPQCReconciler) ensureCA(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent, spec pqcv1alpha1.SigningSpec) (*caState, error) {
	st, err := r.listCAs(ctx, cr, c)
	if err != nil {
		return nil, err
	}
	want := caGen{max(spec.RootGeneration, 1), max(spec.IntermediateGeneration, 1)}
	st.want = want
	if len(st.cas) > 0 {
		newest := &st.cas[0]
		switch {
		case want == newest.gen:
			st.target = newest
			return st, nil
		case want.root < newest.gen.root || want.intermediate < newest.gen.intermediate:
			// The instance was recreated below its last CA generation.
			return nil, &blockedError{
				reason: "CAGenerationBehind",
				msg: fmt.Sprintf("%s CA Secret %s exists for root generation %d, intermediate generation %d; set %s.rootGeneration to %d and %s.intermediateGeneration to %d or higher",
					c.title, newest.secret.Name, newest.gen.root, newest.gen.intermediate, c.path, newest.gen.root, c.path, newest.gen.intermediate),
			}
		case st.rotating():
			st.target, st.held = newest, true
			return st, nil
		}
	}
	if err := r.issueCA(ctx, cr, c, spec, st, want); err != nil {
		return nil, err
	}
	st, err = r.listCAs(ctx, cr, c)
	if err != nil {
		return nil, err
	}
	st.want = want
	if st.target = st.find(want); st.target == nil || st.target != &st.cas[0] {
		return nil, fmt.Errorf("%s CA %s not newest after it was issued", c.title, want)
	}
	return st, nil
}

// issueCA creates the intermediate want, under a new root when want raises
// the root generation, after the weaker-algorithm checks.
func (r *SecureSignPQCReconciler) issueCA(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent, spec pqcv1alpha1.SigningSpec, st *caState, want caGen) error {
	subject := fmt.Sprintf("%s/%s %s", cr.Namespace, cr.Name, c.title)
	var newest *caKey
	if len(st.cas) > 0 {
		newest = &st.cas[0]
	}
	var root *pki.Root
	if newest == nil || want.root > newest.gen.root {
		if newest != nil {
			accepted := func(a *pqcv1alpha1.WeakerAlgorithmAcceptance) bool { return a.RootGeneration == want.root }
			hint := fmt.Sprintf("rootGeneration: %d", want.root)
			if err := weakerRefused(spec, c.path, fmt.Sprintf("%s root generation %d", c.title, want.root), newest.ca.Root, accepted, hint); err != nil {
				return err
			}
			if err := weakerRefused(spec, c.path, fmt.Sprintf("%s intermediate %s", c.title, want), newest.ca.Intermediate, accepted, hint); err != nil {
				return err
			}
		}
		key := types.NamespacedName{Namespace: cr.Namespace, Name: c.rootSecretName(cr.Name, want.root)}
		labels := c.labels(cr, c.roleRoot)
		labels[LabelRootGeneration] = strconv.Itoa(int(want.root))
		s, err := r.ensureSecret(ctx, key, labels, func() (map[string][]byte, error) {
			root, err := pki.NewRoot(spec.Algorithm, fmt.Sprintf("%s root %d", subject, want.root), time.Now())
			if err != nil {
				return nil, err
			}
			return root.Encode()
		})
		if err != nil {
			return err
		}
		if root, err = pki.DecodeRoot(s.Data); err != nil {
			return invalidSecret(s.Name, err)
		}
	} else {
		rk := st.rootKey(want.root)
		if rk == nil {
			return &blockedError{
				reason: "RootKeyUnavailable",
				msg: fmt.Sprintf("the %s root CA generation %d has no private key Secret %s, so it cannot issue intermediate %s; raise %s.rootGeneration to %d to issue a new root and intermediate",
					c.title, want.root, c.rootSecretName(cr.Name, want.root), want, c.path, want.root+1),
			}
		}
		accepted := func(a *pqcv1alpha1.WeakerAlgorithmAcceptance) bool {
			return a.IntermediateGeneration == want.intermediate
		}
		hint := fmt.Sprintf("intermediateGeneration: %d", want.intermediate)
		if err := weakerRefused(spec, c.path, fmt.Sprintf("%s intermediate %s", c.title, want), newest.ca.Intermediate, accepted, hint); err != nil {
			return err
		}
		root = rk.root
	}
	key := types.NamespacedName{Namespace: cr.Namespace, Name: c.intermediateSecretName(cr.Name, want)}
	_, err := r.ensureSecret(ctx, key, c.genLabels(cr, c.roleIntermediate, want), func() (map[string][]byte, error) {
		ca, err := root.IssueIntermediate(spec.Algorithm, fmt.Sprintf("%s intermediate %s", subject, want), c.eku, time.Now())
		if err != nil {
			return nil, err
		}
		return ca.Encode()
	})
	if err == nil && newest != nil {
		logf.FromContext(ctx).Info("issued CA", "component", c.name, "generation", want.String(), "previous", newest.gen.String())
	}
	return err
}

// weakerRefused refuses a key at spec's algorithm weaker than the one in
// cert, unless spec.acceptWeakerAlgorithm names the algorithm and accepted
// says it covers this key. what names the key; hint is the acceptance field
// that would cover it.
func weakerRefused(spec pqcv1alpha1.SigningSpec, path, what string, cert *x509.Certificate, accepted func(*pqcv1alpha1.WeakerAlgorithmAcceptance) bool, hint string) error {
	inUse, err := pki.AlgorithmOf(cert.PublicKey)
	if err != nil {
		return err
	}
	if a := spec.AcceptWeakerAlgorithm; a != nil && a.Algorithm == spec.Algorithm && accepted(a) {
		return nil
	}
	if pki.Strength(spec.Algorithm) >= pki.Strength(inUse) {
		return nil
	}
	return &blockedError{
		reason: "WeakerAlgorithmNotAccepted",
		msg: fmt.Sprintf("%s would use %s, weaker than %s in use; set %s.acceptWeakerAlgorithm to {algorithm: %s, %s} to accept it",
			what, spec.Algorithm, inUse, path, spec.Algorithm, hint),
	}
}

// markCAsRetired marks the chain records of c's intermediates other than
// target retired, so their trusted root entries end, before retireCAs
// deletes their keys.
func (r *SecureSignPQCReconciler) markCAsRetired(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent, st *caState, now time.Time) error {
	for _, k := range st.cas {
		if k.gen != st.target.gen {
			if err := r.markChainRetired(ctx, cr, c, k.gen, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// retireCAs deletes the private keys of c's intermediates other than
// target, which markCAsRetired has marked, and of roots with no
// intermediate left under them.
func (r *SecureSignPQCReconciler) retireCAs(ctx context.Context, c caComponent, st *caState) error {
	var kept []caKey
	for _, k := range st.cas {
		if k.gen == st.target.gen {
			kept = append(kept, k)
			continue
		}
		if err := r.Delete(ctx, k.secret, client.Preconditions{UID: &k.secret.UID}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		logf.FromContext(ctx).Info("retired CA", "component", c.name, "kind", "intermediate", "generation", k.gen.String(), "secret", k.secret.Name)
	}
	st.cas = kept
	var roots []rootKey
	for _, rk := range st.roots {
		if rk.gen >= st.target.gen.root || slices.ContainsFunc(kept, func(k caKey) bool { return k.gen.root == rk.gen }) {
			roots = append(roots, rk)
			continue
		}
		if err := r.Delete(ctx, rk.secret, client.Preconditions{UID: &rk.secret.UID}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		logf.FromContext(ctx).Info("retired CA", "component", c.name, "kind", "root", "generation", rk.gen, "secret", rk.secret.Name)
	}
	st.roots = roots
	return nil
}

// setRotation sets c's rotation condition, recording an event when a raise
// starts to wait for the rotation in progress.
func (r *SecureSignPQCReconciler) setRotation(cr *pqcv1alpha1.SecureSignPQC, c caComponent, st *caState) {
	cond := metav1.Condition{Type: c.rotationCondition, Status: metav1.ConditionFalse, Reason: "NoRotation",
		Message: fmt.Sprintf("%s intermediate %s is the only CA in use", c.title, st.target.gen)}
	switch {
	case st.held:
		cond.Status, cond.Reason = metav1.ConditionTrue, "RotationHeld"
		cond.Message = fmt.Sprintf("%s CA %s waits for the rotation to %s to finish rolling out", c.title, st.want, st.target.gen)
	case st.rotating():
		cond.Status, cond.Reason = metav1.ConditionTrue, "RollingOut"
		cond.Message = fmt.Sprintf("%s CA %s is rolling out; the previous CA retires once no pod uses it", c.title, st.target.gen)
	}
	if old := meta.FindStatusCondition(cr.Status.Conditions, cond.Type); cond.Reason == "RotationHeld" && (old == nil || old.Reason != cond.Reason) && r.Recorder != nil {
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, cond.Reason, "RotateCA", "%s", cond.Message)
	}
	setCondition(cr, cond)
}

// expiryCheck is a certificate in use that the CertificatesExpiring
// condition watches.
type expiryCheck struct {
	what string
	cert *x509.Certificate
	// fix is what to do when this certificate expires first; caFix is set
	// when that rotates a CA.
	fix    string
	caFix  bool
	signer bool
}

// caFixes are what to do about c's target intermediate and root expiring.
type caFixes struct {
	intermediate, root expiryCheck
}

// caExpiryChecks returns c's CAs in use, target first, and the fixes for
// its target intermediate and root.
func caExpiryChecks(c caComponent, st *caState) ([]expiryCheck, caFixes) {
	target := st.target
	fixes := caFixes{
		intermediate: expiryCheck{fix: fmt.Sprintf("raise %s.intermediateGeneration to issue a new intermediate", c.path), caFix: true},
		root:         expiryCheck{fix: fmt.Sprintf("raise %s.rootGeneration to issue a new root and intermediate", c.path), caFix: true},
	}
	// An intermediate that ends with its root, or whose root has no key,
	// cannot be replaced under that root.
	if !target.ca.Intermediate.NotAfter.Before(target.ca.Root.NotAfter) || st.rootKey(target.gen.root) == nil {
		fixes.intermediate = fixes.root
	}
	inter, root := fixes.intermediate, fixes.root
	inter.what, inter.cert = fmt.Sprintf("%s intermediate CA %s", c.title, target.gen), target.ca.Intermediate
	root.what, root.cert = fmt.Sprintf("%s root CA %d", c.title, target.gen.root), target.ca.Root
	checks := []expiryCheck{inter, root}
	for _, k := range st.cas {
		if k.gen != target.gen {
			checks = append(checks, expiryCheck{what: fmt.Sprintf("%s intermediate CA %s (in use until %s rolls out)", c.title, k.gen, target.gen),
				cert: k.ca.Intermediate, fix: finishRollout})
		}
	}
	return checks, fixes
}

// finishRollout is the fix for a certificate still in use only until a
// rotation rolls out.
const finishRollout = "finish that rollout"

// checkExpiry sets the CertificatesExpiring condition from the certificate
// in checks that expires first, recording an event when it turns True.
// soon is the end of the warning window.
func (r *SecureSignPQCReconciler) checkExpiry(cr *pqcv1alpha1.SecureSignPQC, checks []expiryCheck, soon time.Time) {
	soonest := checks[0]
	for _, c := range checks[1:] {
		if c.cert.NotAfter.Before(soonest.cert.NotAfter) {
			soonest = c
		}
	}
	c := metav1.Condition{Type: pqcv1alpha1.ConditionCertificatesExpiring}
	expires := soonest.cert.NotAfter.UTC().Format(time.RFC3339)
	switch {
	case soonest.cert.NotAfter.After(soon):
		c.Status, c.Reason = metav1.ConditionFalse, "NotExpiring"
		c.Message = fmt.Sprintf("%s certificate expires first, at %s", soonest.what, expires)
	case soonest.signer && !soonest.caFix:
		c.Status, c.Reason = metav1.ConditionTrue, "SignerExpiring"
		c.Message = fmt.Sprintf("%s certificate expires at %s; %s", soonest.what, expires, soonest.fix)
	default:
		c.Status, c.Reason = metav1.ConditionTrue, "CAExpiring"
		c.Message = fmt.Sprintf("%s certificate expires at %s; %s", soonest.what, expires, soonest.fix)
	}
	if c.Status == metav1.ConditionTrue && !meta.IsStatusConditionTrue(cr.Status.Conditions, c.Type) && r.Recorder != nil {
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, c.Reason, "CheckExpiry", "%s", c.Message)
	}
	setCondition(cr, c)
}
