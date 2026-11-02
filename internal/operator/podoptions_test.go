package operator

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
)

func tsaDeploymentOf(ctx context.Context, ns string) (*appsv1.Deployment, error) {
	var d appsv1.Deployment
	err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d)
	return &d, err
}

// Pod options reach the TSA Deployment, a template the API server refuses
// blocks the instance until the options change, and a Deployment that
// cannot create its pods is reported in TSAReady.
func TestPodOptions(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "podopts")
	cr := newInstance(ns)
	cr.Spec.TSA.Tolerations = []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
	cr.Spec.TSA.PriorityClassName = "tsa-critical"
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "scheduling options applied", func() error {
		d, err := tsaDeploymentOf(ctx, ns)
		if err != nil {
			return err
		}
		pod := d.Spec.Template.Spec
		if len(pod.Tolerations) != 1 || pod.Tolerations[0].Key != "dedicated" || pod.PriorityClassName != "tsa-critical" {
			return fmt.Errorf("tolerations %v, priorityClassName %q", pod.Tolerations, pod.PriorityClassName)
		}
		if got := pod.Containers[0].Resources.Limits[corev1.ResourceMemory]; got.String() != "256Mi" {
			return fmt.Errorf("default memory limit %s", got.String())
		}
		return nil
	})

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) {
		s.TSA.Resources = &pqcv1alpha1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
		}
	})
	eventually(t, 30*time.Second, "request above its limit blocked", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionFalse, "InvalidPodOptions")
	})

	want := pqcv1alpha1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
	}
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Resources = &want })
	eventually(t, 30*time.Second, "resources replace the defaults", func() error {
		d, err := tsaDeploymentOf(ctx, ns)
		if err != nil {
			return err
		}
		res := d.Spec.Template.Spec.Containers[0].Resources
		eq := func(a, b corev1.ResourceList) bool {
			return maps.EqualFunc(a, b, func(x, y resource.Quantity) bool { return x.Cmp(y) == 0 })
		}
		if !eq(res.Requests, want.Requests) || !eq(res.Limits, want.Limits) {
			return fmt.Errorf("resources %v", res)
		}
		return nil
	})

	// As the Deployment controller reports pods refused for an exceeded
	// quota.
	eventually(t, 30*time.Second, "Deployment marked failing", func() error {
		d, err := tsaDeploymentOf(ctx, ns)
		if err != nil {
			return err
		}
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation,
			Conditions: []appsv1.DeploymentCondition{{
				Type: appsv1.DeploymentReplicaFailure, Status: corev1.ConditionTrue, Reason: "FailedCreate",
				Message: `pods "demo-tsa-1" is forbidden: exceeded quota: compute`,
			}},
		}
		return k8s.Status().Update(ctx, d)
	})
	eventually(t, 30*time.Second, "ReplicaFailure reported", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionTSAReady, metav1.ConditionFalse, "ReplicaFailure"); err != nil {
			return err
		}
		if c := meta.FindStatusCondition(cr.Status.Conditions, pqcv1alpha1.ConditionTSAReady); !strings.Contains(c.Message, "exceeded quota") {
			return fmt.Errorf("TSAReady message %q", c.Message)
		}
		return nil
	})
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "Ready", func() error {
		return conditionIs(getCR(t, ns), pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "AllComponentsReady")
	})
}
