package main

import (
	"bytes"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/sealhouse/secure-sign-pqc-operator/config"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

const testImage = "localhost:5001/sealhouse/secure-sign-pqc-operator@sha256:d470fc01f1a13b993c25f36ef8ecd3f6b65150c2e79a9a1920f0bde27590ceda"

// kustomize builds config/default from disk; the rest comes from config.Files.
var configDir = filepath.Join("..", "..", "config")

// kustomizeBuild renders config/default with the pinned kustomize, which
// make test passes in KUSTOMIZE.
func kustomizeBuild(t *testing.T) []byte {
	t.Helper()
	bin := os.Getenv("KUSTOMIZE")
	if bin == "" {
		t.Fatal("KUSTOMIZE is not set; run the tests with make test")
	}
	out, err := exec.Command(bin, "build", filepath.Join(configDir, "default")).Output()
	if err != nil {
		t.Fatalf("kustomize build: %v", err)
	}
	return out
}

func options(t *testing.T, manifests []byte) Options {
	t.Helper()
	base, err := config.Files.ReadFile("manifests/bases/secure-sign-pqc-operator.clusterserviceversion.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sample, err := config.Files.ReadFile("samples/pqc_v1alpha1_securesignpqc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := supported.Load()
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Package:       "secure-sign-pqc-operator",
		Version:       "0.1.0-alpha.7",
		Replaces:      "secure-sign-pqc-operator.v0.1.0-alpha.6",
		Channels:      []string{"alpha"},
		OperatorImage: testImage,
		Base:          base,
		Manifests:     manifests,
		Samples:       [][]byte{sample},
		Profiles:      profiles,
	}
}

func csvOf(t *testing.T, b *Bundle) *operatorsv1alpha1.ClusterServiceVersion {
	t.Helper()
	var csv operatorsv1alpha1.ClusterServiceVersion
	if err := yaml.Unmarshal(b.Files[filepath.Join("manifests", "secure-sign-pqc-operator.clusterserviceversion.yaml")], &csv); err != nil {
		t.Fatal(err)
	}
	return &csv
}

func TestBundleFromConfigIsValid(t *testing.T) {
	o := options(t, kustomizeBuild(t))
	b, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := Validate(dir); err != nil {
		t.Fatal(err)
	}

	csv := csvOf(t, b)
	if csv.Name != "secure-sign-pqc-operator.v0.1.0-alpha.7" || csv.Spec.Replaces != o.Replaces {
		t.Errorf("name %s replaces %s", csv.Name, csv.Spec.Replaces)
	}
	for _, m := range csv.Spec.InstallModes {
		if m.Supported != (m.Type == operatorsv1alpha1.InstallModeTypeAllNamespaces) {
			t.Errorf("install mode %s supported=%v; only AllNamespaces is supported", m.Type, m.Supported)
		}
	}
	deployments := csv.Spec.InstallStrategy.StrategySpec.DeploymentSpecs
	if len(deployments) != 1 {
		t.Fatalf("%d deployments", len(deployments))
	}
	for _, c := range deployments[0].Spec.Template.Spec.Containers {
		if c.Name == managerContainer && c.Image != testImage {
			t.Errorf("manager image %s", c.Image)
		}
		if len(c.Command) > 0 {
			t.Errorf("container %s overrides the image entrypoint with %v", c.Name, c.Command)
		}
	}
	if csv.Annotations["containerImage"] != testImage {
		t.Errorf("containerImage %s", csv.Annotations["containerImage"])
	}

	// Every operand image the operator can deploy is a related image.
	related := make([]string, 0, len(csv.Spec.RelatedImages))
	for _, r := range csv.Spec.RelatedImages {
		related = append(related, r.Image)
	}
	for _, p := range o.Profiles {
		for key, img := range p.Images {
			if !slices.Contains(related, img) {
				t.Errorf("%s %s (%s) is not a related image", p.Version, key, img)
			}
		}
	}

	// The roles bound to the operator are permissions, not manifests.
	for name := range b.Files {
		if strings.Contains(name, "manager-role") || strings.Contains(name, "leader-election") ||
			strings.HasSuffix(name, "_namespace.yaml") || strings.HasSuffix(name, "_serviceaccount.yaml") {
			t.Errorf("bundle ships %s", name)
		}
	}
}

// The manager reads each operand image from the CSV, as its related image
// says, so a pipeline rewriting one rewrites both.
func TestBundleOperandImageEnv(t *testing.T) {
	o := options(t, kustomizeBuild(t))
	b, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	csv := csvOf(t, b)
	var env []corev1.EnvVar
	for _, c := range csv.Spec.InstallStrategy.StrategySpec.DeploymentSpecs[0].Spec.Template.Spec.Containers {
		if c.Name == managerContainer {
			env = c.Env
		}
	}
	fromCSV, err := supported.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range fromCSV {
		for key := range p.Images {
			p.Images[key] = "unset@sha256:0"
		}
	}
	used, err := fromCSV.Override(func(name string) (string, bool) {
		i := slices.IndexFunc(env, func(e corev1.EnvVar) bool { return e.Name == name })
		if i < 0 {
			return "", false
		}
		return env[i].Value, true
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range o.Profiles {
		got, _ := fromCSV.Lookup(p.Version)
		if !maps.Equal(got.Images, p.Images) {
			t.Errorf("%s from the CSV env %v, want %v", p.Version, got.Images, p.Images)
		}
	}
	if operands := len(csv.Spec.RelatedImages) - 1; len(used) != operands {
		t.Errorf("%d image variables for %d related operand images", len(used), operands)
	}
}

// The operator's and Prometheus's accounts get their roles as CSV
// permissions, which OLM binds in the namespace it installs into.
func TestBundlePermissions(t *testing.T) {
	b, err := Generate(options(t, kustomizeBuild(t)))
	if err != nil {
		t.Fatal(err)
	}
	csv := csvOf(t, b)
	strategy := csv.Spec.InstallStrategy.StrategySpec
	accounts := make([]string, 0, len(strategy.ClusterPermissions))
	for _, p := range strategy.ClusterPermissions {
		accounts = append(accounts, p.ServiceAccountName)
	}
	if len(strategy.Permissions) != 1 || strategy.Permissions[0].ServiceAccountName != "rhtas-pqc-controller-manager" ||
		!slices.Equal(accounts, []string{"rhtas-pqc-controller-manager", "rhtas-pqc-metrics-scraper"}) {
		t.Fatalf("permissions %+v, clusterPermissions for %v", strategy.Permissions, accounts)
	}
	if _, ok := b.Files[filepath.Join("manifests", "rhtas-pqc-metrics-reader_clusterrole.yaml")]; !ok {
		t.Errorf("metrics-reader ClusterRole not shipped; files %v", slices.Sorted(maps.Keys(b.Files)))
	}
	// Prometheus's account may read /metrics and nothing else.
	scraper := strategy.ClusterPermissions[1].Rules
	if len(scraper) != 1 || !slices.Equal(scraper[0].NonResourceURLs, []string{"/metrics"}) || !slices.Equal(scraper[0].Verbs, []string{"get"}) ||
		len(scraper[0].Resources) != 0 {
		t.Errorf("scraper rules %+v", scraper)
	}
}

func TestBundleIsReproducible(t *testing.T) {
	o := options(t, kustomizeBuild(t))
	first, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Files) != len(second.Files) {
		t.Fatalf("%d files, then %d", len(first.Files), len(second.Files))
	}
	for name, data := range first.Files {
		if !bytes.Equal(data, second.Files[name]) {
			t.Errorf("%s differs between runs", name)
		}
	}
}

func TestGenerateRejects(t *testing.T) {
	manifests := kustomizeBuild(t)
	cases := map[string]func(*Options){
		"image by tag": func(o *Options) {
			o.OperatorImage = "localhost:5001/sealhouse/secure-sign-pqc-operator:latest"
		},
		"build metadata": func(o *Options) { o.Version = "0.1.0-alpha.7+abc" },
		"no channel":     func(o *Options) { o.Channels = nil },
		"unknown kind": func(o *Options) {
			o.Manifests = append(slices.Clone(o.Manifests), []byte("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: stray\n")...)
		},
		"binding to an account outside the build": func(o *Options) {
			o.Manifests = append(slices.Clone(o.Manifests), []byte(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: stray
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: rhtas-pqc-metrics-reader
subjects:
- kind: ServiceAccount
  name: prometheus-k8s
  namespace: openshift-monitoring
`)...)
		},
		"unbound account": func(o *Options) {
			o.Manifests = append(slices.Clone(o.Manifests), []byte("---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: stray\n")...)
		},
		"binding to another subject": func(o *Options) {
			o.Manifests = append(slices.Clone(o.Manifests), []byte(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: stray
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: rhtas-pqc-metrics-reader
subjects:
- kind: User
  name: someone
`)...)
		},
		"undescribed CRD version": func(o *Options) {
			o.Base = bytes.Replace(o.Base, []byte("version: v1alpha1"), []byte("version: v1beta1"), 1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := options(t, manifests)
			mutate(&o)
			if _, err := Generate(o); err == nil {
				t.Fatal("Generate succeeded")
			}
		})
	}
}
