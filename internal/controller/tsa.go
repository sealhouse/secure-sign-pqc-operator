package controller

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
)

const (
	tsaPort       = 3000
	tsaSignerPath = "/var/run/rhtas-pqc/tsa"
	// TSASignerHashAnnotation rolls the TSA pods when the signer changes, and
	// shows which signer a pod template uses.
	TSASignerHashAnnotation = "pqc.rhtas.redhat.com/tsa-signer-hash"
)

// Labels on the TSA key Secrets.
const (
	LabelKeyRole        = "pqc.rhtas.redhat.com/key-role"
	LabelKeyGeneration  = "pqc.rhtas.redhat.com/key-generation"
	RoleTSARoot         = "tsa-root"
	RoleTSAIntermediate = "tsa-intermediate"
	RoleTSAChain        = "tsa-chain"
	RoleTSASigner       = "tsa-signer"
)

// maxRetiredSigners bounds the retired keys kept in status.
const maxRetiredSigners = 16

// TSARootSecretName is the Secret holding a TSA root CA key.
func TSARootSecretName(instance string, root int32) string {
	return tsaCA.rootSecretName(instance, root)
}

// TSAIntermediateSecretName is the Secret holding a TSA intermediate CA key.
func TSAIntermediateSecretName(instance string, root, intermediate int32) string {
	return tsaCA.intermediateSecretName(instance, caGen{root, intermediate})
}

// TSAChainName is the ConfigMap recording a TSA intermediate's public chain.
func TSAChainName(instance string, root, intermediate int32) string {
	return tsaCA.chainName(instance, caGen{root, intermediate})
}

// TSASignerSecretName is the Secret holding a TSA signing key and chain,
// for one signer generation under one intermediate.
func TSASignerSecretName(instance string, root, intermediate, generation int32) string {
	return fmt.Sprintf("%s-tsa-signer-%d-%d-%d", instance, root, intermediate, generation)
}

// TSAName is the name of the TSA Deployment and Service.
func TSAName(instance string) string { return instance + "-tsa" }

var tsaCA = caComponent{
	name:              "tsa",
	component:         "timestamp-authority",
	title:             "TSA",
	path:              tsaSigning,
	eku:               pki.TSAIntermediateEKU,
	roleRoot:          RoleTSARoot,
	roleIntermediate:  RoleTSAIntermediate,
	roleChain:         RoleTSAChain,
	rotationCondition: pqcv1alpha1.ConditionTSACARotation,
	authorities: func(tr *prototrustroot.TrustedRoot) *[]*prototrustroot.CertificateAuthority {
		return &tr.TimestampAuthorities
	},
	url: func(cr *pqcv1alpha1.SecureSignPQC) string { return TSAURL(cr) + "/api/v1/timestamp" },
}

func tsaSelector(cr *pqcv1alpha1.SecureSignPQC) map[string]string {
	return map[string]string{
		LabelName:     "tsa",
		LabelInstance: cr.Name,
	}
}

func tsaLabels(cr *pqcv1alpha1.SecureSignPQC) map[string]string {
	l := tsaSelector(cr)
	l[LabelComponent] = "timestamp-authority"
	l[LabelManagedBy] = ManagedBy
	l[labelVersion] = cr.Spec.Version
	return l
}

// ensureSecret returns the Secret key, creating it immutable with labels and
// generate's data if it does not exist.
func (r *SecureSignPQCReconciler) ensureSecret(ctx context.Context, key types.NamespacedName, labels map[string]string, generate func() (map[string][]byte, error)) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	created, err := r.createIfAbsent(ctx, key, s, func() error {
		data, err := generate()
		if err != nil {
			return err
		}
		*s = corev1.Secret{
			Namespace: key.Namespace, Name: key.Name, Labels: labels,
			Type:      corev1.SecretTypeOpaque,
			Immutable: new(true),
			Data:      data,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if created {
		logf.FromContext(ctx).Info("created key Secret", "secret", key.Name, "role", labels[LabelKeyRole])
	}
	return s, nil
}

// createIfAbsent reads key into obj and, if there is no such object,
// creates it as fill sets obj. obj ends as the API server holds it: the
// object created, or one a concurrent writer created first.
func (r *SecureSignPQCReconciler) createIfAbsent(ctx context.Context, key types.NamespacedName, obj client.Object, fill func() error) (bool, error) {
	err := r.APIReader.Get(ctx, key, obj)
	if err == nil {
		return false, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, err
	}
	if err := fill(); err != nil {
		return false, err
	}
	if err := r.Create(ctx, obj); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return false, err
		}
		return false, r.APIReader.Get(ctx, key, obj)
	}
	return true, nil
}

// tsaSigner is one signer Secret, decoded.
type tsaSigner struct {
	generation int32
	ca         caGen
	secret     *corev1.Secret
	chain      *pki.TSAChain
}

// ensureTSASigner returns the signer for the current generation under the
// target intermediate, issuing it if its Secret does not exist, and the
// other signers, newest first.
func (r *SecureSignPQCReconciler) ensureTSASigner(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, st *caState) (*tsaSigner, []tsaSigner, error) {
	var list corev1.SecretList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(cr.Namespace),
		client.MatchingLabels{LabelInstance: cr.Name, LabelKeyRole: RoleTSASigner}); err != nil {
		return nil, nil, err
	}
	spec := cr.Spec.TSA.Signing
	gen := signerGeneration(spec)
	var current *tsaSigner
	var older []tsaSigner
	for i := range list.Items {
		s := &list.Items[i]
		g, err := labelGeneration(s, LabelKeyGeneration)
		if err != nil {
			return nil, nil, invalidSecret(s.Name, err)
		}
		cg, err := labelCAGen(s)
		if err != nil {
			return nil, nil, invalidSecret(s.Name, err)
		}
		if g > gen {
			// The instance was recreated below its last generation.
			return nil, nil, &blockedError{
				reason: "SignerGenerationBehind",
				msg: fmt.Sprintf("signer Secret %s exists for generation %d; set %s.signerGeneration to %d or higher",
					s.Name, g, tsaSigning, g),
			}
		}
		k := st.find(cg)
		if k == nil {
			return nil, nil, invalidSecret(s.Name, fmt.Errorf("issued by TSA intermediate %s, which has no CA Secret", cg))
		}
		chain, err := pki.DecodeTSAChain(s.Data, k.ca)
		if err != nil {
			return nil, nil, invalidSecret(s.Name, err)
		}
		signer := tsaSigner{generation: g, ca: cg, secret: s, chain: chain}
		if g == gen && cg == st.target.gen {
			current = &signer
		} else {
			older = append(older, signer)
		}
	}
	slices.SortFunc(older, func(a, b tsaSigner) int {
		if c := cmp.Compare(b.generation, a.generation); c != 0 {
			return c
		}
		return b.ca.compare(a.ca)
	})
	if current != nil {
		return current, older, nil
	}

	if len(older) > 0 {
		target := st.target.gen
		accepted := func(a *pqcv1alpha1.WeakerAlgorithmAcceptance) bool {
			switch {
			case a.SignerGeneration == gen:
				return true
			case st.rootRotation():
				return a.RootGeneration == target.root
			case st.rotating():
				return a.IntermediateGeneration == target.intermediate
			}
			return false
		}
		hint := fmt.Sprintf("signerGeneration: %d", gen)
		if err := weakerRefused(spec, tsaSigning, fmt.Sprintf("signer generation %d", gen), older[0].chain.Leaf, accepted, hint); err != nil {
			return nil, nil, err
		}
	}
	target := st.target
	key := types.NamespacedName{Namespace: cr.Namespace, Name: TSASignerSecretName(cr.Name, target.gen.root, target.gen.intermediate, gen)}
	labels := tsaCA.genLabels(cr, RoleTSASigner, target.gen)
	labels[LabelKeyGeneration] = strconv.Itoa(int(gen))
	s, err := r.ensureSecret(ctx, key, labels, func() (map[string][]byte, error) {
		chain, err := target.ca.IssueLeaf(spec.Algorithm, fmt.Sprintf("%s/%s generation %d", cr.Namespace, cr.Name, gen), time.Now())
		if err != nil {
			return nil, err
		}
		return chain.Encode()
	})
	if err != nil {
		return nil, nil, err
	}
	if g, err := labelGeneration(s, LabelKeyGeneration); err != nil || g != gen {
		return nil, nil, invalidSecret(s.Name, fmt.Errorf("generation label does not match generation %d", gen))
	}
	chain, err := pki.DecodeTSAChain(s.Data, target.ca)
	if err != nil {
		return nil, nil, invalidSecret(s.Name, err)
	}
	return &tsaSigner{generation: gen, ca: target.gen, secret: s, chain: chain}, older, nil
}

// blockedError is a spec the operator will not act on until a person
// changes it.
type blockedError struct {
	reason, msg string
}

func (e *blockedError) Error() string { return e.msg }

// invalidSignerError is a key Secret or chain record the operator will not
// use.
type invalidSignerError struct {
	object string
	err    error
}

func (e *invalidSignerError) Error() string {
	return fmt.Sprintf("%s: %v", e.object, e.err)
}

func invalidSecret(name string, err error) error {
	return &invalidSignerError{object: "secret " + name, err: err}
}

func (e *invalidSignerError) Unwrap() error { return e.err }

func signerHash(data map[string][]byte) string {
	h := sha256.New()
	for _, k := range []string{pki.KeyPEM, pki.ChainPEM} {
		h.Write([]byte(k))
		h.Write(data[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// tsaResources are the TSA container's requests and limits unless
// spec.tsa.resources is set.
var tsaResources = pqcv1alpha1.ResourceRequirements{
	Requests: corev1.ResourceList{
		corev1.ResourceCPU:    resourceQuantity("50m"),
		corev1.ResourceMemory: resourceQuantity("64Mi"),
	},
	Limits: corev1.ResourceList{
		corev1.ResourceMemory: resourceQuantity("256Mi"),
	},
}

// tsaDeployment renders the TSA Deployment.
func tsaDeployment(cr *pqcv1alpha1.SecureSignPQC, image, signerSecret string, signer map[string][]byte, fips string) (*appsv1ac.DeploymentApplyConfiguration, error) {
	labels := tsaLabels(cr)
	args := []string{
		"serve",
		// An empty host listens on every address, IPv4 and IPv6.
		"--host=",
		fmt.Sprintf("--port=%d", tsaPort),
		"--timestamp-signer=file",
		"--timestamp-signer-hash=sha512",
		"--experimental-enable-pqc",
		"--file-signer-key-path=" + tsaSignerPath + "/" + pki.KeyPEM,
		"--certificate-chain-path=" + tsaSignerPath + "/" + pki.ChainPEM,
	}
	probe := func() *corev1ac.ProbeApplyConfiguration {
		return corev1ac.Probe().WithHTTPGet(corev1ac.HTTPGetAction().
			WithPath("/ping").WithPort(intstr.FromString("http")))
	}
	container := corev1ac.Container().
		WithName("tsa").
		WithImage(image).
		WithArgs(args...).
		WithPorts(corev1ac.ContainerPort().WithName("http").WithContainerPort(tsaPort).WithProtocol(corev1.ProtocolTCP)).
		WithReadinessProbe(probe().WithPeriodSeconds(5)).
		WithLivenessProbe(probe().WithPeriodSeconds(20).WithFailureThreshold(3)).
		WithEnv(corev1ac.EnvVar().WithName("GODEBUG").WithValue("fips140="+fips)).
		WithSecurityContext(restrictedContainerSecurityContext()).
		WithVolumeMounts(
			corev1ac.VolumeMount().WithName("signer").WithMountPath(tsaSignerPath).WithReadOnly(true),
			corev1ac.VolumeMount().WithName("tmp").WithMountPath("/tmp"),
		)

	pod := corev1ac.PodSpec().
		WithAutomountServiceAccountToken(false).
		WithSecurityContext(restrictedPodSecurityContext()).
		WithVolumes(
			corev1ac.Volume().WithName("signer").WithSecret(corev1ac.SecretVolumeSource().
				WithSecretName(signerSecret).
				WithItems(
					corev1ac.KeyToPath().WithKey(pki.KeyPEM).WithPath(pki.KeyPEM),
					corev1ac.KeyToPath().WithKey(pki.ChainPEM).WithPath(pki.ChainPEM),
				)),
			corev1ac.Volume().WithName("tmp").WithEmptyDir(corev1ac.EmptyDirVolumeSource()),
		)
	if err := applyPodOptions(pod, container, cr.Spec.TSA.PodOptions, tsaResources); err != nil {
		return nil, err
	}
	pod.WithContainers(container)

	return appsv1ac.Deployment(TSAName(cr.Name), cr.Namespace).
		WithLabels(labels).
		WithOwnerReferences(ownerReference(cr)).
		WithSpec(appsv1ac.DeploymentSpec().
			WithReplicas(ptr.Deref(cr.Spec.TSA.Replicas, 1)).
			WithSelector(metav1ac.LabelSelector().WithMatchLabels(tsaSelector(cr))).
			WithTemplate(corev1ac.PodTemplateSpec().
				WithLabels(labels).
				WithAnnotations(map[string]string{TSASignerHashAnnotation: signerHash(signer)}).
				WithSpec(pod))), nil
}

func tsaService(cr *pqcv1alpha1.SecureSignPQC) *corev1ac.ServiceApplyConfiguration {
	return corev1ac.Service(TSAName(cr.Name), cr.Namespace).
		WithLabels(tsaLabels(cr)).
		WithOwnerReferences(ownerReference(cr)).
		WithSpec(corev1ac.ServiceSpec().
			WithType(corev1.ServiceTypeClusterIP).
			WithSelector(tsaSelector(cr)).
			WithPorts(corev1ac.ServicePort().
				WithName("http").
				WithPort(tsaPort).
				WithTargetPort(intstr.FromString("http")).
				WithProtocol(corev1.ProtocolTCP)))
}

// TSAURL is the in-cluster base URL of an instance's TSA.
func TSAURL(cr *pqcv1alpha1.SecureSignPQC) string {
	return fmt.Sprintf("http://%s.%s.svc:%d", TSAName(cr.Name), cr.Namespace, tsaPort)
}

// reconcileTSA converges the TSA and reports its rollout: available once
// every pod runs the requested version with the current signer.
func (r *SecureSignPQCReconciler) reconcileTSA(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, profile *versions.Profile) (rollout, error) {
	image, err := profile.Image(versions.ImageTSA)
	if err != nil {
		return rollout{}, err
	}
	fips, err := fipsMode(cr)
	if err != nil {
		return rollout{}, err
	}
	st, err := r.ensureCA(ctx, cr, tsaCA, cr.Spec.TSA.Signing)
	if err != nil {
		return rollout{}, err
	}
	current, older, err := r.ensureTSASigner(ctx, cr, st)
	if err != nil {
		return rollout{}, err
	}
	records, err := r.ensureChainRecords(ctx, cr, tsaCA, st)
	if err != nil {
		return rollout{}, err
	}
	if err := r.publishTrustedRoot(ctx, cr, []componentRecords{{tsaCA, records}}, tsaCA, st.target.ca); err != nil {
		return rollout{}, err
	}
	if err := r.Apply(ctx, tsaService(cr), client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		return rollout{}, err
	}
	now := time.Now()
	soon := now.Add(r.Settings.Load().ExpiryWarning)
	r.checkExpiry(cr, tsaExpiryChecks(st, current, older, soon), soon)
	hash := signerHash(current.secret.Data)
	d, err := tsaDeployment(cr, image, current.secret.Name, current.secret.Data, fips)
	if err != nil {
		return rollout{}, err
	}
	if err := r.Apply(ctx, d, client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		if apierrors.IsInvalid(err) {
			// The pod options are the only part of the template a user sets.
			return rollout{}, &blockedError{
				reason: "InvalidPodOptions",
				msg:    fmt.Sprintf("the TSA Deployment was refused; check spec.tsa's resources and scheduling fields: %v", err),
			}
		}
		return rollout{}, err
	}
	// Read from the API server: deleting a key on a stale view would take it
	// from pods that still use it.
	var live appsv1.Deployment
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: TSAName(cr.Name)}, &live); err != nil {
		return rollout{}, err
	}
	ro := deploymentRollout(&live, image)
	if live.Spec.Template.Annotations[TSASignerHashAnnotation] != hash {
		ro.available = false
	}
	r.setRotation(cr, tsaCA, st)

	if !ro.available || (len(older) == 0 && !st.rotating()) {
		setTSAKeys(cr, st, records, current, older, ro.available, nil)
		return ro, nil
	}
	// Every pod uses the current signer: retire the rest. The CA records
	// are marked first and status is written before any key is deleted.
	if err := r.markCAsRetired(ctx, cr, tsaCA, st, now); err != nil {
		return rollout{}, err
	}
	if records, err = r.ensureChainRecords(ctx, cr, tsaCA, st); err != nil {
		return rollout{}, err
	}
	base := cr.DeepCopy()
	setTSAKeys(cr, st, records, current, nil, true, older)
	if err := r.applyStatus(ctx, base, cr); err != nil {
		return rollout{}, err
	}
	for _, s := range older {
		err := r.Delete(ctx, s.secret, client.Preconditions{UID: &s.secret.UID})
		if err != nil && !apierrors.IsNotFound(err) {
			return rollout{}, err
		}
		logf.FromContext(ctx).Info("retired TSA signer", "secret", s.secret.Name, "generation", s.generation, "ca", s.ca.String())
	}
	if err := r.retireCAs(ctx, tsaCA, st); err != nil {
		return rollout{}, err
	}
	if err := r.publishTrustedRoot(ctx, cr, []componentRecords{{tsaCA, records}}, tsaCA, st.target.ca); err != nil {
		return rollout{}, err
	}
	r.setRotation(cr, tsaCA, st)
	return ro, nil
}

// fipsMode is the fips140 GODEBUG setting for cr's components. off is
// refused, and the TSA would not start with a value it does not know.
func fipsMode(cr *pqcv1alpha1.SecureSignPQC) (string, error) {
	v, ok := cr.Annotations[pqcv1alpha1.FIPSAnnotation]
	switch {
	case !ok:
		return "auto", nil
	case v == "auto", v == "on", v == "only":
		return v, nil
	}
	return "", &blockedError{
		reason: "InvalidFIPSMode",
		msg:    fmt.Sprintf("annotation %s is %q: use auto, on or only", pqcv1alpha1.FIPSAnnotation, v),
	}
}

// tsaExpiryChecks are the TSA's CAs and signers in use. soon is the end of
// the expiry warning window.
func tsaExpiryChecks(st *caState, current *tsaSigner, older []tsaSigner, soon time.Time) []expiryCheck {
	checks, fixes := caExpiryChecks(tsaCA, st)
	// The CAs come first, so a signer that expires with them names the CA.
	// A signer cannot outlive its intermediate, so a new one helps only if
	// the intermediate has time left.
	cur := expiryCheck{fix: fmt.Sprintf("raise %s.signerGeneration to issue a new one", tsaSigning)}
	if !st.target.ca.Intermediate.NotAfter.After(soon) {
		cur = fixes.intermediate
	}
	cur.what, cur.cert, cur.signer = fmt.Sprintf("TSA signer generation %d", current.generation), current.chain.Leaf, true
	checks = append(checks, cur)
	for _, s := range older {
		checks = append(checks, expiryCheck{
			what: fmt.Sprintf("TSA signer generation %d of intermediate %s (in use until generation %d rolls out)", s.generation, s.ca, current.generation),
			cert: s.chain.Leaf, fix: finishRollout, signer: true,
		})
	}
	return checks
}

// setTSAKeys records the CAs and signers in status.
func setTSAKeys(cr *pqcv1alpha1.SecureSignPQC, st *caState, records []chainRecord, current *tsaSigner, older []tsaSigner, currentInUse bool, retiring []tsaSigner) {
	cr.Status.TSA.CAs = caStatus(records, st.target.gen, st.rotating() && !currentInUse)

	stage := pqcv1alpha1.KeyPending
	if currentInUse {
		stage = pqcv1alpha1.KeyActive
	}
	signers := []pqcv1alpha1.KeyStatus{signerStatus(current, stage)}
	for i := range older {
		signers = append(signers, signerStatus(&older[i], pqcv1alpha1.KeyActive))
	}
	now := metav1.Now()
	var retired []pqcv1alpha1.KeyStatus
	for i := range retiring {
		k := signerStatus(&retiring[i], pqcv1alpha1.KeyRetired)
		k.RetiredAt = &now
		retired = append(retired, k)
	}
	// Carry retired entries forward, except for a key listed above: a key
	// marked retired whose delete failed still has its Secret, and is
	// reported from that until it is gone.
	listed := func(serial string) bool {
		same := func(k pqcv1alpha1.KeyStatus) bool { return k.SerialNumber == serial }
		return slices.ContainsFunc(signers, same) || slices.ContainsFunc(retired, same)
	}
	for _, k := range cr.Status.TSA.Signers {
		if k.Stage == pqcv1alpha1.KeyRetired && !listed(k.SerialNumber) {
			retired = append(retired, k)
		}
	}
	slices.SortStableFunc(retired, func(a, b pqcv1alpha1.KeyStatus) int { return cmp.Compare(b.Generation, a.Generation) })
	if len(retired) > maxRetiredSigners {
		retired = retired[:maxRetiredSigners]
	}
	cr.Status.TSA.Signers = append(signers, retired...)
}

func signerStatus(s *tsaSigner, stage pqcv1alpha1.KeyStage) pqcv1alpha1.KeyStatus {
	return pqcv1alpha1.KeyStatus{
		Generation:        s.generation,
		CertificateStatus: certificateStatus(s.chain.Leaf, s.chain.Intermediate, stage),
	}
}

// certificateStatus describes cert at stage, issued by issuer, which is nil
// for a root.
func certificateStatus(cert, issuer *x509.Certificate, stage pqcv1alpha1.KeyStage) pqcv1alpha1.CertificateStatus {
	a, _ := pki.AlgorithmOf(cert.PublicKey)
	s := pqcv1alpha1.CertificateStatus{
		Algorithm:    a,
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    metav1.NewTime(cert.NotBefore),
		NotAfter:     metav1.NewTime(cert.NotAfter),
		Stage:        stage,
	}
	if issuer != nil {
		s.IssuerSerialNumber = issuer.SerialNumber.Text(16)
	}
	return s
}
