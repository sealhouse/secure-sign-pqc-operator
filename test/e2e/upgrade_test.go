//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	operatorsv1 "github.com/operator-framework/api/pkg/operators/v1"
	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/operator"
)

const (
	crdName = "securesignpqcs.pqc.rhtas.redhat.com"
	// upgradeInstance is the instance created on the previous alpha head and
	// checked again after the upgrade.
	upgradeInstance = "upgrade"
	// nonDefaultInstance is created on the previous alpha head with a
	// non-default algorithm and signer generation.
	nonDefaultInstance   = "upgrade-non-default"
	nonDefaultAlgorithm  = pqcv1alpha1.MLDSA87
	nonDefaultGeneration = 2
	// leaseDuration is the operator's default leader lease (internal/tuning).
	leaseDuration = 137 * time.Second
	// handoverLimit is the longest a new operator process may take, from its
	// container's start, to lead after an in-place CSV replacement.
	handoverLimit = 90 * time.Second
)

// upgrade records what installUpgrade saw, for TestUpgrade.
type upgrade struct {
	from, to        string
	instance        client.ObjectKey
	keysBefore      map[string]types.UID
	keysAfter       map[string]types.UID
	leader          string
	handover        time.Duration
	readyAfter      bool
	readyConditions []metav1.Condition
	nonDefault      nonDefaultUpgrade
}

// nonDefaultUpgrade records the non-default instance across the upgrade.
type nonDefaultUpgrade struct {
	keysBefore map[string]types.UID
	ready      bool
	conditions []metav1.Condition
	keysAfter  map[string]types.UID
	signers    []pqcv1alpha1.KeyStatus
}

// upgraded is set when the suite installed through an upgrade.
var upgraded *upgrade

// installUpgrade installs published.PreviousCSV, the alpha head the new
// bundle replaces, with an instance in upgradeNamespace, then upgrades it to
// published.CSV the way a cluster on the alpha channel would.
func installUpgrade(ctx context.Context) error {
	u := &upgrade{from: published.PreviousCSV, to: published.CSV,
		instance: client.ObjectKey{Namespace: upgradeNamespace, Name: upgradeInstance}}
	if err := uninstall(ctx); err != nil {
		return err
	}
	if err := deleteCRD(ctx); err != nil {
		return err
	}
	if err := catalogFor(ctx, published.CatalogImage); err != nil {
		return err
	}
	og := &operatorsv1.OperatorGroup{Namespace: operatorNamespace, Name: operatorNamespace}
	if err := createOrUpdate(ctx, og, func() { og.Spec = operatorsv1.OperatorGroupSpec{} }); err != nil {
		return err
	}
	sub := &operatorsv1alpha1.Subscription{
		Namespace: operatorNamespace, Name: packageName,
		Spec: &operatorsv1alpha1.SubscriptionSpec{
			CatalogSource:          catalogName,
			CatalogSourceNamespace: catalogNamespace,
			Package:                packageName,
			Channel:                channel,
			StartingCSV:            u.from,
			InstallPlanApproval:    operatorsv1alpha1.ApprovalManual,
		},
	}
	if err := k8s.Create(ctx, sub); err != nil {
		return err
	}
	if err := approve(ctx, u.from); err != nil {
		return err
	}
	if err := waitInstalled(ctx, u.from); err != nil {
		return err
	}

	cr := &pqcv1alpha1.SecureSignPQC{
		Namespace: u.instance.Namespace, Name: u.instance.Name,
		Spec: pqcv1alpha1.SecureSignPQCSpec{Version: "2.0"},
	}
	if err := k8s.Create(ctx, cr); err != nil {
		return err
	}
	if err := waitReady(ctx, cr); err != nil {
		return fmt.Errorf("instance on %s: %w", u.from, err)
	}
	var err error
	if u.keysBefore, err = keySecrets(ctx, u.instance); err != nil {
		return err
	}
	if len(u.keysBefore) < 2 {
		return fmt.Errorf("instance on %s has key Secrets %v, want the CA and a signer", u.from, u.keysBefore)
	}
	nonDefault, err := createNonDefault(ctx, &u.nonDefault)
	if err != nil {
		return fmt.Errorf("instance with non-default settings on %s: %w", u.from, err)
	}
	oldPods, err := operatorPodNames(ctx)
	if err != nil {
		return err
	}

	if err := approve(ctx, u.to); err != nil {
		return err
	}
	if err := waitInstalled(ctx, u.to); err != nil {
		return err
	}
	if err := poll(ctx, 2*time.Minute, func() (bool, error) {
		old := client.ObjectKey{Namespace: operatorNamespace, Name: u.from}
		err := k8s.Get(ctx, old, &operatorsv1alpha1.ClusterServiceVersion{})
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	}); err != nil {
		return fmt.Errorf("CSV %s still present after the upgrade: %w", u.from, err)
	}
	if u.leader, u.handover, err = handover(ctx, oldPods); err != nil {
		return err
	}

	// The new operator reconciles the instance it inherited.
	u.readyAfter = waitReady(ctx, cr) == nil
	u.readyConditions = cr.Status.Conditions
	if u.keysAfter, err = keySecrets(ctx, u.instance); err != nil {
		return err
	}
	if err := checkNonDefault(ctx, nonDefault, &u.nonDefault); err != nil {
		return err
	}
	upgraded = u
	return nil
}

// createNonDefault creates nonDefaultInstance on the previous head and
// waits for it to be Ready with its signer. The spec is written as JSON, as
// it is stored, not through the Go types: a field the new types renamed
// must reach the upgrade as the previous head stored it.
func createNonDefault(ctx context.Context, t *nonDefaultUpgrade) (*pqcv1alpha1.SecureSignPQC, error) {
	stored := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": pqcv1alpha1.GroupVersion.String(),
		"kind":       "SecureSignPQC",
		"metadata":   map[string]any{"namespace": upgradeNamespace, "name": nonDefaultInstance},
		"spec": map[string]any{
			"version": "2.0",
			"tsa": map[string]any{"signing": map[string]any{
				"algorithm":        string(nonDefaultAlgorithm),
				"signerGeneration": int64(nonDefaultGeneration),
			}},
		},
	}}
	if err := k8s.Create(ctx, stored); err != nil {
		return nil, err
	}
	cr := &pqcv1alpha1.SecureSignPQC{Namespace: upgradeNamespace, Name: nonDefaultInstance}
	if err := waitReady(ctx, cr); err != nil {
		return nil, err
	}
	if s := cr.Status.TSA.Signers; len(s) == 0 ||
		s[0].Generation != nonDefaultGeneration || s[0].Algorithm != nonDefaultAlgorithm {
		return nil, fmt.Errorf("signers %+v, want generation %d %s first", s, nonDefaultGeneration, nonDefaultAlgorithm)
	}
	var err error
	t.keysBefore, err = keySecrets(ctx, client.ObjectKeyFromObject(cr))
	return cr, err
}

// checkNonDefault records the non-default instance on the new operator.
func checkNonDefault(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, t *nonDefaultUpgrade) error {
	t.ready = waitReady(ctx, cr) == nil
	t.conditions = cr.Status.Conditions
	t.signers = cr.Status.TSA.Signers
	var err error
	t.keysAfter, err = keySecrets(ctx, client.ObjectKeyFromObject(cr))
	return err
}

// TestUpgrade checks the upgrade installUpgrade ran: the instance created on
// the previous head is Ready on the new operator with the same keys, and the
// new operator took the leader lease without waiting it out.
func TestUpgrade(t *testing.T) {
	if upgraded == nil {
		t.Skip("no previous alpha head: this is the first alpha")
	}
	u := upgraded
	t.Logf("upgraded %s -> %s; %s leads %s after its container started",
		u.from, u.to, u.leader, u.handover.Round(100*time.Millisecond))
	if !u.readyAfter {
		t.Errorf("instance %s not Ready after the upgrade: %+v", u.instance, u.readyConditions)
	}
	if !maps.Equal(u.keysBefore, u.keysAfter) {
		t.Errorf("key Secrets changed across the upgrade:\nbefore %v\nafter  %v", u.keysBefore, u.keysAfter)
	}
	if u.handover > handoverLimit {
		t.Errorf("new operator took %s to lead (limit %s, lease %s): "+
			"the in-place CSV replacement left the old lease to expire",
			u.handover.Round(time.Second), handoverLimit, leaseDuration)
	}
	cr := &pqcv1alpha1.SecureSignPQC{Namespace: u.instance.Namespace, Name: u.instance.Name}
	deleteInstance(t, cr)
}

// TestUpgradeKeepsSigningSettings checks the instance created with
// ML-DSA-87 at signer generation 2 stays Ready across the upgrade on the
// same keys, without the new operator issuing one.
func TestUpgradeKeepsSigningSettings(t *testing.T) {
	if upgraded == nil {
		t.Skip("no previous alpha head: this is the first alpha")
	}
	nd := upgraded.nonDefault
	if !nd.ready {
		t.Errorf("instance %s not Ready after the upgrade: %+v", nonDefaultInstance, nd.conditions)
	}
	if !maps.Equal(nd.keysBefore, nd.keysAfter) {
		t.Errorf("key Secrets changed across the upgrade:\nbefore %v\nafter  %v", nd.keysBefore, nd.keysAfter)
	}
	if len(nd.signers) == 0 ||
		nd.signers[0].Generation != nonDefaultGeneration || nd.signers[0].Algorithm != nonDefaultAlgorithm {
		t.Errorf("signers %+v, want generation %d %s first", nd.signers, nonDefaultGeneration, nonDefaultAlgorithm)
	}
	deleteInstance(t, &pqcv1alpha1.SecureSignPQC{Namespace: upgradeNamespace, Name: nonDefaultInstance})
}

// catalogFor points the catalog source at image and waits until it serves
// published.CSV at the head of the channel.
func catalogFor(ctx context.Context, image string) error {
	cs := &operatorsv1alpha1.CatalogSource{Namespace: catalogNamespace, Name: catalogName}
	if err := createOrUpdate(ctx, cs, func() {
		cs.Spec = operatorsv1alpha1.CatalogSourceSpec{
			SourceType:  operatorsv1alpha1.SourceTypeGrpc,
			Image:       image,
			DisplayName: "sealhouse alpha",
			Publisher:   "sealhouse",
		}
	}); err != nil {
		return err
	}
	if err := poll(ctx, 3*time.Minute, func() (bool, error) {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(cs), cs); err != nil {
			return false, err
		}
		c := cs.Status.GRPCConnectionState
		return c != nil && c.LastObservedState == "READY" && cs.Status.RegistryServiceStatus != nil, nil
	}); err != nil {
		return fmt.Errorf("catalog source %s not ready: %w", catalogName, err)
	}
	// The gRPC state can still describe the previous catalog pod after an
	// image change; the package manifest shows what the catalog serves.
	if err := poll(ctx, 3*time.Minute, func() (bool, error) {
		return servesCSV(ctx)
	}); err != nil {
		return fmt.Errorf("catalog %s does not serve %s on %s: %w", catalogName, published.CSV, channel, err)
	}
	return nil
}

// approve approves the subscription's install plan for csv once OLM has
// made it.
func approve(ctx context.Context, csv string) error {
	sub := &operatorsv1alpha1.Subscription{Namespace: operatorNamespace, Name: packageName}
	var plan operatorsv1alpha1.InstallPlan
	if err := poll(ctx, 5*time.Minute, func() (bool, error) {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(sub), sub); err != nil {
			return false, err
		}
		if sub.Status.InstallPlanRef == nil {
			return false, nil
		}
		planKey := client.ObjectKey{Namespace: operatorNamespace, Name: sub.Status.InstallPlanRef.Name}
		if err := k8s.Get(ctx, planKey, &plan); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		return slices.Contains(plan.Spec.ClusterServiceVersionNames, csv), nil
	}); err != nil {
		return fmt.Errorf("no install plan for %s (subscription state %q): %w", csv, sub.Status.State, err)
	}
	if plan.Spec.Approved {
		return nil
	}
	plan.Spec.Approved = true
	return k8s.Update(ctx, &plan)
}

// waitInstalled waits until the subscription has installed csv and the CSV
// has succeeded.
func waitInstalled(ctx context.Context, name string) error {
	sub := &operatorsv1alpha1.Subscription{Namespace: operatorNamespace, Name: packageName}
	var csv operatorsv1alpha1.ClusterServiceVersion
	err := poll(ctx, 5*time.Minute, func() (bool, error) {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(sub), sub); err != nil {
			return false, err
		}
		if sub.Status.InstalledCSV != name {
			return false, nil
		}
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: name}, &csv); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		if csv.Status.Phase == operatorsv1alpha1.CSVPhaseFailed {
			return false, fmt.Errorf("CSV %s failed: %s", csv.Name, csv.Status.Message)
		}
		return csv.Status.Phase == operatorsv1alpha1.CSVPhaseSucceeded, nil
	})
	if err != nil {
		return fmt.Errorf("subscription to %s (installed %q, CSV phase %q: %s): %w",
			name, sub.Status.InstalledCSV, csv.Status.Phase, csv.Status.Message, err)
	}
	return nil
}

func waitReady(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) error {
	return poll(ctx, 5*time.Minute, func() (bool, error) {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(cr), cr); err != nil {
			return false, err
		}
		return cr.Status.ObservedGeneration == cr.Generation &&
			meta.IsStatusConditionTrue(cr.Status.Conditions, pqcv1alpha1.ConditionReady), nil
	})
}

// keySecrets maps the instance's key Secrets to their UIDs.
func keySecrets(ctx context.Context, instance client.ObjectKey) (map[string]types.UID, error) {
	var all corev1.SecretList
	if err := k8s.List(ctx, &all, client.InNamespace(instance.Namespace),
		client.MatchingLabels{controller.LabelInstance: instance.Name},
		client.HasLabels{controller.LabelKeyRole}); err != nil {
		return nil, err
	}
	keys := map[string]types.UID{}
	for _, s := range all.Items {
		keys[s.Name] = s.UID
	}
	return keys, nil
}

func operatorPodNames(ctx context.Context) ([]string, error) {
	var pods corev1.PodList
	if err := k8s.List(ctx, &pods, client.InNamespace(operatorNamespace), operatorPods); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(pods.Items))
	for _, p := range pods.Items {
		names = append(names, p.Name)
	}
	return names, nil
}

// handover waits for an operator pod not in old to hold the leader lease and
// returns it with the time from its container's start to its lease
// acquisition: the pod's own start time also counts its image pull.
func handover(ctx context.Context, old []string) (string, time.Duration, error) {
	lease := &coordinationv1.Lease{}
	key := client.ObjectKey{Namespace: operatorNamespace, Name: operator.LeaderElectionID}
	var pod corev1.Pod
	if err := pollEvery(ctx, time.Second, leaseDuration+2*time.Minute, func() (bool, error) {
		if err := k8s.Get(ctx, key, lease); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		holder := ""
		if lease.Spec.HolderIdentity != nil {
			holder = *lease.Spec.HolderIdentity
		}
		if holder == "" || slices.Contains(old, holder) {
			return false, nil
		}
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: holder}, &pod); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		return len(pod.Status.ContainerStatuses) == 1 && pod.Status.ContainerStatuses[0].State.Running != nil &&
			lease.Spec.AcquireTime != nil, nil
	}); err != nil {
		holder := "<none>"
		if lease.Spec.HolderIdentity != nil {
			holder = *lease.Spec.HolderIdentity
		}
		return "", 0, fmt.Errorf("no new operator pod took the lease within %s (holder %s, old pods %v): %w",
			leaseDuration+2*time.Minute, holder, old, err)
	}
	return pod.Name, lease.Spec.AcquireTime.Sub(pod.Status.ContainerStatuses[0].State.Running.StartedAt.Time), nil
}

func deleteCRD(ctx context.Context) error {
	crd := &apiextensionsv1.CustomResourceDefinition{Name: crdName}
	if err := k8s.Delete(ctx, crd); client.IgnoreNotFound(err) != nil {
		return err
	}
	return poll(ctx, 2*time.Minute, func() (bool, error) {
		err := k8s.Get(ctx, client.ObjectKeyFromObject(crd), crd)
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	})
}
