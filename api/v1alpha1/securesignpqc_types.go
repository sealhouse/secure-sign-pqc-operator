/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Algorithm is an ML-DSA parameter set from FIPS 204.
// +kubebuilder:validation:Enum=ML-DSA-44;ML-DSA-65;ML-DSA-87
type Algorithm string

const (
	MLDSA44 Algorithm = "ML-DSA-44"
	MLDSA65 Algorithm = "ML-DSA-65"
	MLDSA87 Algorithm = "ML-DSA-87"
)

// SecureSignPQCSpec defines the desired state of SecureSignPQC.
type SecureSignPQCSpec struct {
	// version is the product version this instance runs.
	// +kubebuilder:validation:Enum="2.0"
	// +kubebuilder:validation:MaxLength=16
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="version may only stay the same or move to the next supported version"
	// +required
	Version string `json:"version"`

	// tsa configures the RFC 3161 timestamp authority.
	// +kubebuilder:default={}
	// +optional
	TSA TSASpec `json:"tsa,omitzero"`
}

// SigningSpec configures a component's signing keys.
// +kubebuilder:validation:XValidation:rule="!((oldSelf.algorithm == 'ML-DSA-87' && self.algorithm != 'ML-DSA-87') || (oldSelf.algorithm == 'ML-DSA-65' && self.algorithm == 'ML-DSA-44')) || (has(self.acceptWeakerAlgorithm) && self.acceptWeakerAlgorithm.algorithm == self.algorithm && self.acceptWeakerAlgorithm.signerGeneration == (self.signerGeneration > oldSelf.signerGeneration ? self.signerGeneration : oldSelf.signerGeneration + 1))",message="algorithm is weaker than before: set acceptWeakerAlgorithm to this algorithm and the signer generation that will use it"
type SigningSpec struct {
	// algorithm is the ML-DSA parameter set for the next key the operator
	// creates for this component.
	// +kubebuilder:default=ML-DSA-65
	// +optional
	Algorithm Algorithm `json:"algorithm,omitempty"`

	// signerGeneration selects the signing key. Raising it issues a new one.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:XValidation:rule="self >= oldSelf",message="signerGeneration may not decrease"
	// +optional
	SignerGeneration int32 `json:"signerGeneration,omitempty"`

	// acceptWeakerAlgorithm acknowledges one move to a weaker parameter
	// set: the named algorithm, for the named signer generation only.
	// +optional
	AcceptWeakerAlgorithm *WeakerAlgorithmAcceptance `json:"acceptWeakerAlgorithm,omitempty"`
}

// WeakerAlgorithmAcceptance accepts a weaker parameter set for one key.
type WeakerAlgorithmAcceptance struct {
	// algorithm is the weaker parameter set accepted.
	// +required
	Algorithm Algorithm `json:"algorithm"`

	// signerGeneration is the one generation that may use it.
	// +kubebuilder:validation:Minimum=1
	// +required
	SignerGeneration int32 `json:"signerGeneration"`
}

// TSASpec configures the timestamp authority.
type TSASpec struct {
	// replicas is the number of timestamp-server pods.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// signing configures the TSA's CA and signing keys.
	// +kubebuilder:default={algorithm: "ML-DSA-65", signerGeneration: 1}
	// +optional
	Signing SigningSpec `json:"signing,omitzero"`

	// ingress exposes the timestamp authority outside the cluster.
	// +kubebuilder:default={}
	// +optional
	Ingress IngressSpec `json:"ingress,omitzero"`

	PodOptions `json:",inline"`
}

// PodOptions are the settings a user may give a component's pods. Each is
// about what the pods may use or where they run, never what they run or
// mount.
type PodOptions struct {
	// resources are the component container's requests and limits. Set,
	// they replace the operator's defaults as a whole.
	// +optional
	Resources *ResourceRequirements `json:"resources,omitempty"`

	// nodeSelector limits the pods to nodes with these labels.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// tolerations let the pods run on nodes with matching taints.
	// +listType=atomic
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// affinity constrains the nodes the pods run on and their placement
	// relative to other pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// topologySpreadConstraints spread the pods across topology domains.
	// +listType=atomic
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// priorityClassName is the pods' PriorityClass.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// ResourceRequirements are a container's compute resource requests and
// limits.
type ResourceRequirements struct {
	// requests are the resources the container is scheduled with.
	// +optional
	Requests corev1.ResourceList `json:"requests,omitempty"`

	// limits are the most the container may use.
	// +optional
	Limits corev1.ResourceList `json:"limits,omitempty"`
}

// IngressSpec configures an Ingress for a service. On OpenShift the
// platform derives a Route from it with edge TLS termination.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.enabled) || !oldSelf.enabled || (has(self.enabled) && self.enabled)",message="ingress cannot be disabled"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.labels) || (has(self.labels) && self.labels == oldSelf.labels)",message="ingress labels cannot be changed"
type IngressSpec struct {
	// enabled creates the Ingress. It cannot be turned off again.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// host is the Ingress hostname. Without one, OpenShift uses
	// <name>-<namespace>.<cluster ingress domain>; elsewhere it is required.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`
	// +optional
	Host string `json:"host,omitempty"`

	// labels are added to the Ingress, for example to select an ingress
	// controller or router shard. They cannot be changed once set.
	// +kubebuilder:validation:MaxProperties=32
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// KeyStage is where a signing key is in its life.
// +kubebuilder:validation:Enum=Pending;Active;Retired
type KeyStage string

const (
	// KeyPending is a key that exists but is not yet used by every pod.
	KeyPending KeyStage = "Pending"
	// KeyActive is a key in use.
	KeyActive KeyStage = "Active"
	// KeyRetired is a key no longer in use whose private key is deleted.
	KeyRetired KeyStage = "Retired"
)

// KeyStatus describes one signing key.
type KeyStatus struct {
	// generation is the key's signerGeneration; a CA has none.
	// +optional
	Generation int32 `json:"generation,omitempty"`

	// algorithm is the key's ML-DSA parameter set.
	// +required
	Algorithm Algorithm `json:"algorithm"`

	// serialNumber is the hex serial number of the key's certificate.
	// +kubebuilder:validation:MaxLength=64
	// +required
	SerialNumber string `json:"serialNumber"`

	// notBefore and notAfter are the certificate's validity period.
	// +required
	NotBefore metav1.Time `json:"notBefore"`
	// +required
	NotAfter metav1.Time `json:"notAfter"`

	// stage is Pending, Active or Retired.
	// +required
	Stage KeyStage `json:"stage"`

	// retiredAt is when the private key was deleted.
	// +optional
	RetiredAt *metav1.Time `json:"retiredAt,omitempty"`
}

// TSAStatus reports the timestamp authority's endpoints and keys.
type TSAStatus struct {
	// url is the in-cluster base URL of the timestamp authority.
	// +optional
	URL string `json:"url,omitempty"`

	// externalURL is its base URL through its Ingress, when
	// spec.tsa.ingress is enabled.
	// +optional
	ExternalURL string `json:"externalURL,omitempty"`

	// ca is the intermediate CA that issues the signing keys.
	// +optional
	CA *KeyStatus `json:"ca,omitempty"`

	// signers are the signing keys, newest first: the current generation,
	// any older key still in use, then retired keys.
	// +listType=atomic
	// +optional
	Signers []KeyStatus `json:"signers,omitempty"`
}

// Condition types set on SecureSignPQC.
const (
	// ConditionReady is True when every component of the instance is ready.
	ConditionReady = "Ready"
	// ConditionDegraded is True after repeated reconcile failures.
	ConditionDegraded = "Degraded"
	// ConditionTSAReady is True when the timestamp authority is available.
	ConditionTSAReady = "TSAReady"
	// ConditionTSAIngressReady is True when the TSA Ingress is applied; it is
	// absent unless spec.tsa.ingress is enabled.
	ConditionTSAIngressReady = "TSAIngressReady"
	// ConditionCertificatesExpiring is True when a certificate in use
	// expires within the operator's expiry_warning window.
	ConditionCertificatesExpiring = "CertificatesExpiring"
)

// FIPSAnnotation on a SecureSignPQC sets the FIPS 140-3 mode of its
// components: auto, the default, follows the node's kernel; on enables it;
// only also refuses algorithms FIPS does not approve.
const FIPSAnnotation = "pqc.rhtas.redhat.com/fips"

// SecureSignPQCStatus defines the observed state of SecureSignPQC.
type SecureSignPQCStatus struct {
	// version is the product version the running components were last
	// reconciled to.
	// +optional
	Version string `json:"version,omitempty"`

	// observedGeneration is the generation the conditions describe.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions are the per-component conditions plus Ready and Degraded.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// tsa reports the timestamp authority's endpoints and keys.
	// +optional
	TSA TSAStatus `json:"tsa,omitzero"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="TSA CA",type=string,JSONPath=`.status.tsa.ca.algorithm`,priority=1
// +kubebuilder:printcolumn:name="TSA Signer",type=string,JSONPath=`.status.tsa.signers[0].algorithm`,priority=1
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecureSignPQC is one PQC signing deployment at a given product version.
// Its name prefixes Service names and is a label value, so it must be a
// DNS-1035 label short enough for the longest suffix, "-tsa".
// +kubebuilder:validation:XValidation:rule="self.metadata.name.size() <= 59 && self.metadata.name.matches('^[a-z]([-a-z0-9]*[a-z0-9])?$')",message="name must be a DNS-1035 label of at most 59 characters"
type SecureSignPQC struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecureSignPQC
	// +required
	Spec SecureSignPQCSpec `json:"spec"`

	// status defines the observed state of SecureSignPQC
	// +optional
	Status SecureSignPQCStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecureSignPQCList contains a list of SecureSignPQC
type SecureSignPQCList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecureSignPQC `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SecureSignPQC{}, &SecureSignPQCList{})
		return nil
	})
}
