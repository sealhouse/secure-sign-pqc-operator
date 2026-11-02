package controller

import (
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/utils/ptr"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// applyPodOptions sets o on a component's pod spec and container. Without
// o.Resources the container gets defaults.
func applyPodOptions(pod *corev1ac.PodSpecApplyConfiguration, container *corev1ac.ContainerApplyConfiguration, o pqcv1alpha1.PodOptions, defaults pqcv1alpha1.ResourceRequirements) error {
	res := defaults
	if o.Resources != nil {
		res = *o.Resources
	}
	rac := corev1ac.ResourceRequirements()
	if len(res.Requests) > 0 {
		rac.WithRequests(res.Requests)
	}
	if len(res.Limits) > 0 {
		rac.WithLimits(res.Limits)
	}
	container.WithResources(rac)

	if len(o.NodeSelector) > 0 {
		pod.WithNodeSelector(o.NodeSelector)
	}
	for _, t := range o.Tolerations {
		ac, err := applyConfiguration[corev1ac.TolerationApplyConfiguration](t)
		if err != nil {
			return err
		}
		pod.WithTolerations(ac)
	}
	if o.Affinity != nil {
		ac, err := applyConfiguration[corev1ac.AffinityApplyConfiguration](o.Affinity)
		if err != nil {
			return err
		}
		pod.WithAffinity(ac)
	}
	for _, c := range o.TopologySpreadConstraints {
		ac, err := applyConfiguration[corev1ac.TopologySpreadConstraintApplyConfiguration](c)
		if err != nil {
			return err
		}
		pod.WithTopologySpreadConstraints(ac)
	}
	if o.PriorityClassName != "" {
		pod.WithPriorityClassName(o.PriorityClassName)
	}
	return nil
}

// applyConfiguration converts a typed API value to its apply configuration,
// which has the same JSON form.
func applyConfiguration[T any](v any) (*T, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	ac := new(T)
	if err := json.Unmarshal(data, ac); err != nil {
		return nil, fmt.Errorf("convert %T: %w", v, err)
	}
	return ac, nil
}

// rollout is where a component's Deployment stands.
type rollout struct {
	available bool
	// reason and message say why the rollout cannot finish, when the
	// Deployment reports it stuck.
	reason, message string
}

// deploymentRollout is d's rollout, with image the one it should run.
func deploymentRollout(d *appsv1.Deployment, image string) rollout {
	if deploymentAvailable(d, image) {
		return rollout{available: true}
	}
	for _, c := range d.Status.Conditions {
		switch {
		case c.Type == appsv1.DeploymentReplicaFailure && c.Status == corev1.ConditionTrue:
			return rollout{reason: string(appsv1.DeploymentReplicaFailure), message: c.Message}
		case c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse && c.Reason == "ProgressDeadlineExceeded":
			return rollout{reason: c.Reason, message: c.Message}
		}
	}
	return rollout{}
}

// deploymentAvailable reports whether every replica of d runs the current
// template with image.
func deploymentAvailable(d *appsv1.Deployment, image string) bool {
	if d.Generation > d.Status.ObservedGeneration {
		return false
	}
	if len(d.Spec.Template.Spec.Containers) == 0 || d.Spec.Template.Spec.Containers[0].Image != image {
		return false
	}
	want := ptr.Deref(d.Spec.Replicas, 1)
	return d.Status.UpdatedReplicas == want &&
		d.Status.AvailableReplicas == want &&
		d.Status.Replicas == want
}
