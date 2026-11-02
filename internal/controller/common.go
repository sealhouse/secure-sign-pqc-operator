package controller

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

const (
	// FieldOwner is the server-side apply field manager for every object
	// the operator renders.
	FieldOwner = "rhtas-pqc-operator"
	// ManagedBy is the LabelManagedBy value on everything the operator
	// creates, which limits its caches, and the source of its events.
	ManagedBy = "rhtas-pqc-operator"

	// The Kubernetes recommended labels; no Kubernetes library defines them.
	LabelName      = "app.kubernetes.io/name"
	LabelInstance  = "app.kubernetes.io/instance"
	LabelComponent = "app.kubernetes.io/component"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	labelVersion   = "pqc.rhtas.redhat.com/version"
)

func ownerReference(cr *pqcv1alpha1.SecureSignPQC) *metav1ac.OwnerReferenceApplyConfiguration {
	return metav1ac.OwnerReference().
		WithAPIVersion(pqcv1alpha1.GroupVersion.String()).
		WithKind("SecureSignPQC").
		WithName(cr.Name).
		WithUID(cr.UID).
		WithController(true).
		WithBlockOwnerDeletion(true)
}

// restrictedPodSecurityContext meets the restricted Pod Security Standard and
// OpenShift's restricted-v2 SCC.
func restrictedPodSecurityContext() *corev1ac.PodSecurityContextApplyConfiguration {
	return corev1ac.PodSecurityContext().
		WithRunAsNonRoot(true).
		WithSeccompProfile(corev1ac.SeccompProfile().WithType(corev1.SeccompProfileTypeRuntimeDefault))
}

func restrictedContainerSecurityContext() *corev1ac.SecurityContextApplyConfiguration {
	return corev1ac.SecurityContext().
		WithAllowPrivilegeEscalation(false).
		WithReadOnlyRootFilesystem(true).
		WithRunAsNonRoot(true).
		WithCapabilities(corev1ac.Capabilities().WithDrop("ALL")).
		WithSeccompProfile(corev1ac.SeccompProfile().WithType(corev1.SeccompProfileTypeRuntimeDefault))
}

func resourceQuantity(s string) resource.Quantity { return resource.MustParse(s) }
