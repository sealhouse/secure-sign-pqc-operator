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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
	LabelKeyRole       = "pqc.rhtas.redhat.com/key-role"
	LabelKeyGeneration = "pqc.rhtas.redhat.com/key-generation"
	RoleTSACA          = "tsa-ca"
	RoleTSASigner      = "tsa-signer"
)

// maxRetiredSigners bounds the retired keys kept in status.
const maxRetiredSigners = 16

// TSACASecretName is the Secret holding an instance's TSA intermediate CA
// key and certificates.
func TSACASecretName(instance string) string { return instance + "-tsa-ca" }

// TSASignerSecretName is the Secret holding an instance's TSA signing key
// and chain for one signer generation.
func TSASignerSecretName(instance string, generation int32) string {
	return fmt.Sprintf("%s-tsa-signer-%d", instance, generation)
}

// TSAName is the name of the TSA Deployment and Service.
func TSAName(instance string) string { return instance + "-tsa" }

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

func keySecretLabels(cr *pqcv1alpha1.SecureSignPQC, role string) map[string]string {
	return map[string]string{
		LabelName:      "tsa",
		LabelInstance:  cr.Name,
		LabelComponent: "timestamp-authority",
		LabelManagedBy: ManagedBy,
		LabelKeyRole:   role,
	}
}

// ensureSecret returns the Secret key, creating it immutable with labels and
// generate's data if it does not exist.
func (r *SecureSignPQCReconciler) ensureSecret(ctx context.Context, key types.NamespacedName, labels map[string]string, generate func() (map[string][]byte, error)) (*corev1.Secret, error) {
	var s corev1.Secret
	err := r.APIReader.Get(ctx, key, &s)
	if err == nil {
		return &s, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	data, err := generate()
	if err != nil {
		return nil, err
	}
	s = corev1.Secret{
		Namespace: key.Namespace, Name: key.Name, Labels: labels,
		Type:      corev1.SecretTypeOpaque,
		Immutable: new(true),
		Data:      data,
	}
	if err := r.Create(ctx, &s); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
	} else {
		logf.FromContext(ctx).Info("created key Secret", "secret", key.Name, "role", labels[LabelKeyRole])
	}
	// Read back what the API server holds, which is our Secret or one a
	// concurrent writer created first.
	if err := r.APIReader.Get(ctx, key, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ensureTSACA returns the instance's TSA CA, creating it with
// spec.tsa.signing.algorithm if its Secret does not exist.
func (r *SecureSignPQCReconciler) ensureTSACA(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) (*pki.TSACA, error) {
	key := types.NamespacedName{Namespace: cr.Namespace, Name: TSACASecretName(cr.Name)}
	s, err := r.ensureSecret(ctx, key, keySecretLabels(cr, RoleTSACA), func() (map[string][]byte, error) {
		ca, err := pki.NewTSACA(cr.Spec.TSA.Signing.Algorithm, fmt.Sprintf("%s/%s", cr.Namespace, cr.Name), time.Now())
		if err != nil {
			return nil, err
		}
		return ca.Encode()
	})
	if err != nil {
		return nil, err
	}
	ca, err := pki.DecodeTSACA(s.Data)
	if err != nil {
		return nil, &invalidSignerError{secret: key.Name, err: err}
	}
	return ca, nil
}

// tsaSigner is one generation's signer Secret, decoded.
type tsaSigner struct {
	generation int32
	secret     *corev1.Secret
	chain      *pki.TSAChain
}

// listTSASigners returns the instance's signer Secrets, read from the API
// server, newest generation first.
func (r *SecureSignPQCReconciler) listTSASigners(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) ([]corev1.Secret, error) {
	var list corev1.SecretList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(cr.Namespace),
		client.MatchingLabels{LabelInstance: cr.Name, LabelKeyRole: RoleTSASigner}); err != nil {
		return nil, err
	}
	for _, s := range list.Items {
		if _, err := secretGeneration(&s); err != nil {
			return nil, &invalidSignerError{secret: s.Name, err: err}
		}
	}
	slices.SortFunc(list.Items, func(a, b corev1.Secret) int {
		ga, _ := secretGeneration(&a)
		gb, _ := secretGeneration(&b)
		return cmp.Compare(gb, ga)
	})
	return list.Items, nil
}

func secretGeneration(s *corev1.Secret) (int32, error) {
	g, err := strconv.ParseInt(s.Labels[LabelKeyGeneration], 10, 32)
	if err != nil || g < 1 {
		return 0, fmt.Errorf("label %s=%q is not a positive generation", LabelKeyGeneration, s.Labels[LabelKeyGeneration])
	}
	return int32(g), nil
}

// ensureTSASigner returns the signer for the current generation, issuing it
// from ca if its Secret does not exist.
func (r *SecureSignPQCReconciler) ensureTSASigner(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, ca *pki.TSACA) (*tsaSigner, []tsaSigner, error) {
	existing, err := r.listTSASigners(ctx, cr)
	if err != nil {
		return nil, nil, err
	}
	gen := signerGeneration(cr.Spec.TSA.Signing)
	var current *corev1.Secret
	var older []tsaSigner
	for i := range existing {
		s := &existing[i]
		g, _ := secretGeneration(s)
		switch {
		case g > gen:
			// The instance was recreated below its last generation.
			return nil, nil, &blockedError{
				reason: "SignerGenerationBehind",
				msg: fmt.Sprintf("signer Secret %s exists for generation %d; set %s.signerGeneration to %d or higher",
					s.Name, g, tsaSigning, g),
			}
		case g == gen:
			current = s
		case g < gen:
			chain, err := pki.DecodeTSAChain(s.Data, ca)
			if err != nil {
				return nil, nil, &invalidSignerError{secret: s.Name, err: err}
			}
			older = append(older, tsaSigner{generation: g, secret: s, chain: chain})
		}
	}

	if current == nil {
		if len(older) > 0 {
			inUse, err := pki.AlgorithmOf(older[0].chain.Leaf.PublicKey)
			if err != nil {
				return nil, nil, err
			}
			if err := checkWeaker(cr.Spec.TSA.Signing, tsaSigning, inUse); err != nil {
				return nil, nil, err
			}
		}
		key := types.NamespacedName{Namespace: cr.Namespace, Name: TSASignerSecretName(cr.Name, gen)}
		labels := keySecretLabels(cr, RoleTSASigner)
		labels[LabelKeyGeneration] = strconv.Itoa(int(gen))
		current, err = r.ensureSecret(ctx, key, labels, func() (map[string][]byte, error) {
			chain, err := ca.IssueLeaf(cr.Spec.TSA.Signing.Algorithm, fmt.Sprintf("%s/%s generation %d", cr.Namespace, cr.Name, gen), time.Now())
			if err != nil {
				return nil, err
			}
			return chain.Encode()
		})
		if err != nil {
			return nil, nil, err
		}
		if g, err := secretGeneration(current); err != nil || g != gen {
			return nil, nil, &invalidSignerError{secret: current.Name, err: fmt.Errorf("generation label does not match generation %d", gen)}
		}
	}
	chain, err := pki.DecodeTSAChain(current.Data, ca)
	if err != nil {
		return nil, nil, &invalidSignerError{secret: current.Name, err: err}
	}
	return &tsaSigner{generation: gen, secret: current, chain: chain}, older, nil
}

// blockedError is a spec the operator will not act on until a person
// changes it.
type blockedError struct {
	reason, msg string
}

func (e *blockedError) Error() string { return e.msg }

// invalidSignerError is a key Secret the operator will not use.
type invalidSignerError struct {
	secret string
	err    error
}

func (e *invalidSignerError) Error() string {
	return fmt.Sprintf("secret %s: %v", e.secret, e.err)
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
	ca, err := r.ensureTSACA(ctx, cr)
	if err != nil {
		return rollout{}, err
	}
	current, older, err := r.ensureTSASigner(ctx, cr, ca)
	if err != nil {
		return rollout{}, err
	}
	if err := r.Apply(ctx, tsaService(cr), client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		return rollout{}, err
	}
	r.checkExpiry(cr, ca, current, older, time.Now())
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

	if !ro.available || len(older) == 0 {
		setTSAKeys(cr, ca, current, older, ro.available, nil)
		return ro, nil
	}
	base := cr.DeepCopy()
	setTSAKeys(cr, ca, current, nil, true, older)
	if err := r.applyStatus(ctx, base, cr); err != nil {
		return rollout{}, err
	}
	for _, s := range older {
		err := r.Delete(ctx, s.secret, client.Preconditions{UID: &s.secret.UID})
		if err != nil && !apierrors.IsNotFound(err) {
			return rollout{}, err
		}
		logf.FromContext(ctx).Info("retired TSA signer", "secret", s.secret.Name, "generation", s.generation)
	}
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

// checkExpiry sets the CertificatesExpiring condition from the signers in
// use and their CA, recording an event when it turns True.
func (r *SecureSignPQCReconciler) checkExpiry(cr *pqcv1alpha1.SecureSignPQC, ca *pki.TSACA, current *tsaSigner, older []tsaSigner, now time.Time) {
	type checked struct {
		what   string
		cert   *x509.Certificate
		signer bool
	}
	// The CA comes first, so a signer that expires with it names the CA.
	certs := make([]checked, 0, 3+len(older))
	certs = append(certs,
		checked{"intermediate CA", ca.Intermediate, false},
		checked{"root CA", ca.Root, false},
		checked{fmt.Sprintf("signer generation %d", current.generation), current.chain.Leaf, true})
	for _, s := range older {
		certs = append(certs, checked{fmt.Sprintf("signer generation %d (in use until generation %d rolls out)", s.generation, current.generation), s.chain.Leaf, true})
	}
	soonest := certs[0]
	for _, c := range certs[1:] {
		if c.cert.NotAfter.Before(soonest.cert.NotAfter) {
			soonest = c
		}
	}
	warning := r.Settings.Load().ExpiryWarning
	c := metav1.Condition{Type: pqcv1alpha1.ConditionCertificatesExpiring}
	expires := soonest.cert.NotAfter.UTC().Format(time.RFC3339)
	switch {
	case soonest.cert.NotAfter.After(now.Add(warning)):
		c.Status, c.Reason = metav1.ConditionFalse, "NotExpiring"
		c.Message = fmt.Sprintf("TSA %s certificate expires first, at %s", soonest.what, expires)
	case soonest.signer && soonest.cert != current.chain.Leaf && current.chain.Leaf.NotAfter.After(now.Add(warning)):
		c.Status, c.Reason = metav1.ConditionTrue, "SignerExpiring"
		c.Message = fmt.Sprintf("TSA %s certificate expires at %s; finish that rollout", soonest.what, expires)
	case soonest.signer:
		c.Status, c.Reason = metav1.ConditionTrue, "SignerExpiring"
		c.Message = fmt.Sprintf("TSA %s certificate expires at %s; raise %s.signerGeneration to issue a new one", soonest.what, expires, tsaSigning)
	default:
		c.Status, c.Reason = metav1.ConditionTrue, "CAExpiring"
		c.Message = fmt.Sprintf("TSA %s certificate expires at %s; a new signer cannot outlive it, and CA rotation is not supported yet", soonest.what, expires)
	}
	if c.Status == metav1.ConditionTrue && !meta.IsStatusConditionTrue(cr.Status.Conditions, c.Type) && r.Recorder != nil {
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, c.Reason, "CheckExpiry", "%s", c.Message)
	}
	setCondition(cr, c)
}

// setTSAKeys records the CA and signers in status.
func setTSAKeys(cr *pqcv1alpha1.SecureSignPQC, ca *pki.TSACA, current *tsaSigner, older []tsaSigner, currentInUse bool, retiring []tsaSigner) {
	caStatus := keyStatus(ca.Intermediate, 0, pqcv1alpha1.KeyActive)
	cr.Status.TSA.CA = &caStatus

	stage := pqcv1alpha1.KeyPending
	if currentInUse {
		stage = pqcv1alpha1.KeyActive
	}
	signers := []pqcv1alpha1.KeyStatus{keyStatus(current.chain.Leaf, current.generation, stage)}
	for _, s := range older {
		signers = append(signers, keyStatus(s.chain.Leaf, s.generation, pqcv1alpha1.KeyActive))
	}
	now := metav1.Now()
	var retired []pqcv1alpha1.KeyStatus
	for _, s := range retiring {
		k := keyStatus(s.chain.Leaf, s.generation, pqcv1alpha1.KeyRetired)
		k.RetiredAt = &now
		retired = append(retired, k)
	}
	// Carry retired entries forward, except for a generation listed above:
	// a key marked retired whose delete failed still has its Secret, and
	// is reported from that until it is gone.
	listed := func(g int32) bool {
		return slices.ContainsFunc(signers, func(k pqcv1alpha1.KeyStatus) bool { return k.Generation == g }) ||
			slices.ContainsFunc(retired, func(k pqcv1alpha1.KeyStatus) bool { return k.Generation == g })
	}
	for _, k := range cr.Status.TSA.Signers {
		if k.Stage == pqcv1alpha1.KeyRetired && !listed(k.Generation) {
			retired = append(retired, k)
		}
	}
	slices.SortStableFunc(retired, func(a, b pqcv1alpha1.KeyStatus) int { return cmp.Compare(b.Generation, a.Generation) })
	if len(retired) > maxRetiredSigners {
		retired = retired[:maxRetiredSigners]
	}
	cr.Status.TSA.Signers = append(signers, retired...)
}

func keyStatus(cert *x509.Certificate, generation int32, stage pqcv1alpha1.KeyStage) pqcv1alpha1.KeyStatus {
	a, _ := pki.AlgorithmOf(cert.PublicKey)
	return pqcv1alpha1.KeyStatus{
		Generation:   generation,
		Algorithm:    a,
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    metav1.NewTime(cert.NotBefore),
		NotAfter:     metav1.NewTime(cert.NotAfter),
		Stage:        stage,
	}
}
