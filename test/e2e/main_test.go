//go:build e2e

// Package e2e installs the operator from the alpha catalog in the local
// registry through OLM, the way a cluster administrator would, and exercises
// it in namespaces that emulate OpenShift's restricted SCC.
package e2e

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	operatorsv1 "github.com/operator-framework/api/pkg/operators/v1"
	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/operator"
)

const (
	packageName       = "secure-sign-pqc-operator"
	operatorNamespace = "rhtas-pqc-operator"
	// metricsScraper is the bundle's account allowed to read /metrics.
	metricsScraper   = "rhtas-pqc-metrics-scraper"
	channel          = "alpha"
	catalogNamespace = "olm"
	catalogName      = "sealhouse-alpha"
	sccConfigMap     = "sealhouse-scc"
	sccUIDRange      = "openshift.io/sa.scc.uid-range"
	// sccRestricted is the SCC OpenShift admits the operator's and the
	// instances' pods under.
	sccRestricted = "restricted-v2"
)

// operatorPods selects the operator's pods (config/manager).
var operatorPods = client.MatchingLabels{"control-plane": "controller-manager"}

// alpha holds the references hack/publish-alpha.sh wrote.
type alpha struct {
	OperatorImage, BundleImage, CatalogImage, CSV string
	// PreviousCSV is the alpha head the bundle replaces, set for a merge
	// candidate that is not the first alpha; the suite then installs it
	// first and upgrades.
	PreviousCSV string
}

var (
	published alpha
	namespace string
	// upgradeNamespace holds the instance the upgrade carries over.
	upgradeNamespace string
	cfg              *rest.Config
	k8s              client.Client
	clientset        *kubernetes.Clientset
	// openshift is set when the cluster has real SCC admission (MicroShift,
	// OpenShift) rather than the kind emulation.
	openshift bool
)

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e setup:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func setup() error {
	var err error
	if published, err = readAlphaEnv(os.Getenv("ALPHA_ENV")); err != nil {
		return err
	}
	namespace = envOr("E2E_NAMESPACE", "sealhouse-e2e")
	upgradeNamespace = envOr("UPGRADE_NAMESPACE", "sealhouse-upgrade")
	if cfg, err = config.GetConfigWithContext(envOr("KUBE_CONTEXT", "kind-sealhouse")); err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme, operatorsv1alpha1.AddToScheme, operatorsv1.AddToScheme, pqcv1alpha1.AddToScheme,
		apiextensionsv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			return err
		}
	}
	if k8s, err = client.New(cfg, client.Options{Scheme: scheme}); err != nil {
		return err
	}
	if clientset, err = kubernetes.NewForConfig(cfg); err != nil {
		return err
	}
	if openshift, err = servesSCC(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	namespaces := []string{operatorNamespace, namespace}
	if published.PreviousCSV != "" {
		namespaces = append(namespaces, upgradeNamespace)
	}
	for _, ns := range namespaces {
		if _, err := sccUID(ctx, ns); err != nil {
			return fmt.Errorf("%w (run ci/hack/scc-namespace.sh %s)", err, ns)
		}
	}
	if published.PreviousCSV != "" {
		return installUpgrade(ctx)
	}
	return install(ctx)
}

func readAlphaEnv(path string) (alpha, error) {
	var a alpha
	if path == "" {
		return a, fmt.Errorf("ALPHA_ENV is not set; run make test-e2e")
	}
	f, err := os.Open(path)
	if err != nil {
		return a, err
	}
	defer func() { _ = f.Close() }()
	fields := map[string]*string{
		"OPERATOR_IMAGE": &a.OperatorImage, "BUNDLE_IMAGE": &a.BundleImage,
		"CATALOG_IMAGE": &a.CatalogImage, "CSV": &a.CSV,
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), "=")
		if p := fields[k]; ok && p != nil {
			*p = v
		}
		if ok && k == "PREVIOUS_CSV" {
			a.PreviousCSV = v
		}
	}
	if err := s.Err(); err != nil {
		return a, err
	}
	for k, p := range fields {
		if *p == "" {
			return a, fmt.Errorf("%s: no %s", path, k)
		}
	}
	if !strings.Contains(a.CatalogImage, "@sha256:") {
		return a, fmt.Errorf("catalog %s is not pinned by digest", a.CatalogImage)
	}
	return a, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// sccUID returns the UID pods in ns run as.
func sccUID(ctx context.Context, ns string) (int64, error) {
	var nsObj corev1.Namespace
	if err := k8s.Get(ctx, client.ObjectKey{Name: ns}, &nsObj); err != nil {
		return 0, err
	}
	if openshift {
		r, ok := nsObj.Annotations[sccUIDRange]
		if !ok {
			return 0, fmt.Errorf("namespace %s has no %s annotation", ns, sccUIDRange)
		}
		start, _, _ := strings.Cut(r, "/")
		return strconv.ParseInt(start, 10, 64)
	}
	if nsObj.Labels["sealhouse.dev/scc"] != "restricted" {
		return 0, fmt.Errorf("namespace %s is not labelled sealhouse.dev/scc=restricted", ns)
	}
	var cm corev1.ConfigMap
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: sccConfigMap}, &cm); err != nil {
		return 0, err
	}
	return strconv.ParseInt(cm.Data["uid"], 10, 64)
}

// servesSCC reports whether the cluster enforces SecurityContextConstraints.
func servesSCC() (bool, error) {
	groups, err := clientset.Discovery().ServerGroups()
	if err != nil {
		return false, err
	}
	for _, g := range groups.Groups {
		if g.Name == "security.openshift.io" {
			return true, nil
		}
	}
	return false, nil
}

// install replaces any earlier installation with the published CSV: the
// catalog source points at the new catalog digest, and the subscription and
// CSVs of an earlier run are removed, since an alpha CSV built from another
// tree need not be in this CSV's replaces chain.
func install(ctx context.Context) error {
	if err := uninstall(ctx); err != nil {
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
			StartingCSV:            published.CSV,
			InstallPlanApproval:    operatorsv1alpha1.ApprovalAutomatic,
		},
	}
	if err := k8s.Create(ctx, sub); err != nil {
		return err
	}
	return waitInstalled(ctx, published.CSV)
}

// servesCSV reports whether the package manifest from our catalog has the
// published CSV, built from the published operator image, at the head of the
// channel.
func servesCSV(ctx context.Context) (bool, error) {
	pm := &unstructured.Unstructured{}
	pm.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "packages.operators.coreos.com", Version: "v1", Kind: "PackageManifest",
	})
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: packageName}, pm); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if source, _, _ := unstructured.NestedString(pm.Object, "status", "catalogSource"); source != catalogName {
		return false, nil
	}
	channels, _, _ := unstructured.NestedSlice(pm.Object, "status", "channels")
	for _, c := range channels {
		c, _ := c.(map[string]any)
		if c["name"] == channel {
			if c["currentCSV"] != published.CSV {
				return false, nil
			}
			related, _, _ := unstructured.NestedStringSlice(c, "currentCSVDesc", "relatedImages")
			return slices.Contains(related, published.OperatorImage), nil
		}
	}
	return false, nil
}

func uninstall(ctx context.Context) error {
	sub := &operatorsv1alpha1.Subscription{Namespace: operatorNamespace, Name: packageName}
	if err := k8s.Delete(ctx, sub); client.IgnoreNotFound(err) != nil {
		return err
	}
	var csvs operatorsv1alpha1.ClusterServiceVersionList
	if err := k8s.List(ctx, &csvs, client.InNamespace(operatorNamespace)); err != nil {
		return err
	}
	for i := range csvs.Items {
		if csv := &csvs.Items[i]; strings.HasPrefix(csv.Name, packageName+".") {
			if err := k8s.Delete(ctx, csv); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	if err := poll(ctx, 2*time.Minute, func() (bool, error) {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(sub), sub); !apierrors.IsNotFound(err) {
			return false, client.IgnoreNotFound(err)
		}
		if err := k8s.List(ctx, &csvs, client.InNamespace(operatorNamespace)); err != nil {
			return false, err
		}
		for _, csv := range csvs.Items {
			if strings.HasPrefix(csv.Name, packageName+".") {
				return false, nil
			}
		}
		var pods corev1.PodList
		if err := k8s.List(ctx, &pods, client.InNamespace(operatorNamespace), operatorPods); err != nil {
			return false, err
		}
		return len(pods.Items) == 0, nil
	}); err != nil {
		return err
	}
	// OLM removes the CSV's Role together with its Deployment, so the outgoing
	// leader is forbidden to release its lease and the next install would wait
	// out the lease duration.
	lease := &coordinationv1.Lease{
		Namespace: operatorNamespace, Name: operator.LeaderElectionID,
	}
	return client.IgnoreNotFound(k8s.Delete(ctx, lease))
}

// createOrUpdate creates obj with mutate applied, or applies mutate to the
// existing object and updates it.
func createOrUpdate(ctx context.Context, obj client.Object, mutate func()) error {
	err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj)
	if apierrors.IsNotFound(err) {
		mutate()
		return k8s.Create(ctx, obj)
	}
	if err != nil {
		return err
	}
	mutate()
	return k8s.Update(ctx, obj)
}

func poll(ctx context.Context, timeout time.Duration, done func() (bool, error)) error {
	return pollEvery(ctx, 2*time.Second, timeout, done)
}

func pollEvery(ctx context.Context, interval, timeout time.Duration, done func() (bool, error)) error {
	return wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		return done()
	})
}
