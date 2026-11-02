//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/v2_0"
)

// managerContainer is the operator's container in the CSV's Deployment.
const managerContainer = "manager"

// TestOperandImageFromCSV rewrites the TSA image variable on the installed
// CSV, as a release pipeline rewrites image references, and checks the
// operator deploys the rewritten reference rather than its embedded pin.
func TestOperandImageFromCSV(t *testing.T) {
	ctx := t.Context()
	name := versions.RelatedImageEnv(versions.ImageTSA, v2_0.Version)
	pinned, err := managerEnv(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	// The same image under a tag the embedded pin does not have: only the
	// variable can produce this reference.
	repo, digest, ok := strings.Cut(pinned, "@")
	if !ok {
		t.Fatalf("%s=%q has no digest", name, pinned)
	}
	rewritten := repo + ":from-csv@" + digest
	if err := setManagerEnv(ctx, name, rewritten); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := setManagerEnv(context.Background(), name, pinned); err != nil {
			t.Errorf("restoring %s: %v", name, err)
		}
	})

	cr := &pqcv1alpha1.SecureSignPQC{
		Namespace: namespace, Name: "related-image",
		Spec: pqcv1alpha1.SecureSignPQCSpec{Version: v2_0.Version},
	}
	deleteInstance(t, cr)
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteInstance(t, cr) })
	if err := waitReady(ctx, cr); err != nil {
		t.Fatalf("instance not Ready on the rewritten image: %v; conditions %+v", err, cr.Status.Conditions)
	}
	var d appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: controller.TSAName(cr.Name)}, &d); err != nil {
		t.Fatal(err)
	}
	if got := d.Spec.Template.Spec.Containers[0].Image; got != rewritten {
		t.Errorf("TSA image %s, want %s from the CSV's %s", got, rewritten, name)
	}
}

func installedCSV(ctx context.Context) (*operatorsv1alpha1.ClusterServiceVersion, error) {
	csv := &operatorsv1alpha1.ClusterServiceVersion{}
	err := k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: published.CSV}, csv)
	return csv, err
}

// managerContainerOf returns the manager container of the CSV's operator
// Deployment.
func managerContainerOf(csv *operatorsv1alpha1.ClusterServiceVersion) (*corev1.Container, error) {
	specs := csv.Spec.InstallStrategy.StrategySpec.DeploymentSpecs
	if len(specs) != 1 {
		return nil, fmt.Errorf("CSV %s has %d deployments", csv.Name, len(specs))
	}
	containers := specs[0].Spec.Template.Spec.Containers
	i := slices.IndexFunc(containers, func(c corev1.Container) bool { return c.Name == managerContainer })
	if i < 0 {
		return nil, fmt.Errorf("CSV %s has no %s container", csv.Name, managerContainer)
	}
	return &containers[i], nil
}

func managerEnv(ctx context.Context, name string) (string, error) {
	csv, err := installedCSV(ctx)
	if err != nil {
		return "", err
	}
	c, err := managerContainerOf(csv)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(c.Env, func(e corev1.EnvVar) bool { return e.Name == name })
	if i < 0 {
		return "", fmt.Errorf("CSV %s sets no %s", csv.Name, name)
	}
	return c.Env[i].Value, nil
}

// setManagerEnv sets name on the CSV's manager container and waits for OLM
// to roll the operator Deployment onto it.
func setManagerEnv(ctx context.Context, name, value string) error {
	var deployment string
	if err := poll(ctx, time.Minute, func() (bool, error) {
		csv, err := installedCSV(ctx)
		if err != nil {
			return false, err
		}
		deployment = csv.Spec.InstallStrategy.StrategySpec.DeploymentSpecs[0].Name
		c, err := managerContainerOf(csv)
		if err != nil {
			return false, err
		}
		i := slices.IndexFunc(c.Env, func(e corev1.EnvVar) bool { return e.Name == name })
		if i < 0 {
			return false, fmt.Errorf("CSV %s sets no %s", csv.Name, name)
		}
		c.Env[i].Value = value
		err = k8s.Update(ctx, csv)
		if apierrors.IsConflict(err) {
			return false, nil
		}
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("setting %s on CSV %s: %w", name, published.CSV, err)
	}
	var d appsv1.Deployment
	if err := poll(ctx, 5*time.Minute, func() (bool, error) {
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: deployment}, &d); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		containers := d.Spec.Template.Spec.Containers
		i := slices.IndexFunc(containers, func(c corev1.Container) bool { return c.Name == managerContainer })
		if i < 0 || !slices.Contains(containers[i].Env, corev1.EnvVar{Name: name, Value: value}) {
			return false, nil
		}
		want := ptr.Deref(d.Spec.Replicas, 1)
		return d.Status.ObservedGeneration == d.Generation && d.Status.Replicas == want &&
			d.Status.UpdatedReplicas == want && d.Status.AvailableReplicas == want, nil
	}); err != nil {
		return fmt.Errorf("operator Deployment %s not rolled out with %s=%s: %w", deployment, name, value, err)
	}
	return nil
}
