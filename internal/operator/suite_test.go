package operator

import (
	"context"
	"crypto/fips140"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	manifests "github.com/sealhouse/secure-sign-pqc-operator/config"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

var (
	scheme  = runtime.NewScheme()
	testEnv *envtest.Environment
	cfg     *rest.Config
	k8s     client.Client
)

// suiteCleanups run after every test, before envtest stops: processes a
// test file starts once for the whole package.
var suiteCleanups []func()

func TestMain(m *testing.M) {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	utilruntime.Must(pqcv1alpha1.AddToScheme(scheme))
	logf.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true), zap.Level(zapLevel())))

	// The FIPS mode of this process was fixed at start-up from GODEBUG.
	if os.Getenv("GODEBUG") != "" {
		fmt.Fprintf(os.Stderr, "fips140: enabled=%v enforced=%v module=%s\n", fips140.Enabled(), fips140.Enforced(), fips140.Version())
		if err := os.Unsetenv("GODEBUG"); err != nil {
			panic(err)
		}
	}
	crds, err := operatorCRDs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "CRDs:", err)
		os.Exit(1)
	}
	testEnv = &envtest.Environment{
		CRDs:                  crds,
		BinaryAssetsDirectory: envtestAssets(),
	}
	cfg, err = testEnv.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	for _, f := range suiteCleanups {
		f()
	}
	if err := testEnv.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "envtest stop:", err)
	}
	os.Exit(code)
}

func zapLevel() zapcore.Level {
	if os.Getenv("TEST_VERBOSE") != "" {
		return -1
	}
	return 2
}

// operatorCRDs are the generated CRDs in config/crd/bases.
func operatorCRDs() ([]*apiextensionsv1.CustomResourceDefinition, error) {
	paths, err := fs.Glob(manifests.Files, "crd/bases/*.yaml")
	if err != nil {
		return nil, err
	}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, len(paths))
	for _, p := range paths {
		raw, err := manifests.Files.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var crd apiextensionsv1.CustomResourceDefinition
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		crds = append(crds, &crd)
	}
	return crds, nil
}

// envtestAssets finds the binaries `make setup-envtest` installs for this
// platform, unless KUBEBUILDER_ASSETS already points at them.
func envtestAssets() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	entries, _ := os.ReadDir(filepath.Join("..", "..", "bin", "k8s"))
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), "-"+goruntime.GOOS+"-"+goruntime.GOARCH) {
			return filepath.Join("..", "..", "bin", "k8s", e.Name())
		}
	}
	return ""
}

// stubCRD stands in for another project's API: served at v1, any content.
func stubCRD(group, plural, kind string, scope apiextensionsv1.ResourceScope) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		Name: plural + "." + group,
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: group,
			Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: plural, Kind: kind, ListKind: kind + "List"},
			Scope: scope,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name: "v1", Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
					Type: "object", XPreserveUnknownFields: new(true),
				}},
			}},
		},
	}
}

// installCRDs installs crds, and uninstalls them when owner ends.
func installCRDs(t, owner *testing.T, crds ...*apiextensionsv1.CustomResourceDefinition) {
	t.Helper()
	if _, err := envtest.InstallCRDs(cfg, envtest.CRDInstallOptions{CRDs: crds}); err != nil {
		t.Fatal(err)
	}
	owner.Cleanup(func() {
		if err := envtest.UninstallCRDs(cfg, envtest.CRDInstallOptions{CRDs: crds}); err != nil {
			owner.Error(err)
		}
	})
}

// metricValue sums the counters and gauges named name in g whose labels
// include match; 0 when there are none.
func metricValue(t *testing.T, g prometheus.Gatherer, name string, match map[string]string) float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var n float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.Metric {
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			matched := true
			for k, v := range match {
				matched = matched && labels[k] == v
			}
			if matched {
				n += m.GetCounter().GetValue() + m.GetGauge().GetValue()
			}
		}
	}
	return n
}

// configValue is the pqc_operator_config value for setting.
func configValue(t *testing.T, g prometheus.Gatherer, setting string) float64 {
	t.Helper()
	return metricValue(t, g, "pqc_operator_config", map[string]string{"setting": setting})
}

func configValueIs(t *testing.T, g prometheus.Gatherer, setting string, want float64) func() error {
	return func() error {
		if got := configValue(t, g, setting); got != want {
			return fmt.Errorf("%s is %v, want %v", setting, got, want)
		}
		return nil
	}
}

// testSettings are short timings so faults resolve within a test.
func testSettings() tuning.Settings {
	s := tuning.Defaults()
	s.BackoffMax = time.Second
	s.LeaseDuration, s.RenewDeadline, s.RetryPeriod = 6*time.Second, 4*time.Second, time.Second
	return s
}

type running struct {
	// restarts counts the times the manager asked to be replaced, with
	// next the settings of the last.
	restarts atomic.Int32
	next     atomic.Pointer[tuning.Settings]
	reg      *prometheus.Registry
	done     chan error
	cancel   context.CancelFunc
}

// startOperator runs a manager until the test ends.
func startOperator(t *testing.T, namespace string, edit func(*Options)) *running {
	t.Helper()
	return startOperatorWith(t, cfg, namespace, edit)
}

// startOperatorWith is startOperator against restCfg, such as a config that
// reaches the API server through a proxy.
func startOperatorWith(t *testing.T, restCfg *rest.Config, namespace string, edit func(*Options)) *running {
	t.Helper()
	r := &running{reg: prometheus.NewRegistry(), done: make(chan error, 1)}
	profiles, err := supported.Load()
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		Scheme:    scheme,
		Namespace: namespace,
		Env:       testSettings(),
		Effective: testSettings(),
		Profiles:  profiles,
		Manager: ctrl.Options{
			Metrics: metricsserver.Options{BindAddress: "0"},
			// Each test starts its own manager under the same controller name.
			Controller: config.Controller{SkipNameValidation: new(true)},
		},
		Registry: r.reg,
	}
	if edit != nil {
		edit(&o)
	}
	mgr, err := NewManager(restCfg, o, func(s tuning.Settings) { r.next.Store(&s); r.restarts.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-r.done:
			if err != nil {
				t.Logf("manager stopped: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("manager did not stop")
		}
	})
	return r
}

func createNamespace(t *testing.T, prefix string) string {
	t.Helper()
	ns := &corev1.Namespace{GenerateName: prefix + "-"}
	if err := k8s.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	return ns.Name
}

// eventually polls f until it returns nil, failing the test if timeout
// passes first.
func eventually(t *testing.T, timeout time.Duration, what string, f func() error) {
	t.Helper()
	if err := poll(timeout, f); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// gone is an eventually check that obj no longer exists.
func gone(obj client.Object) func() error {
	return func() error {
		err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), obj.DeepCopyObject().(client.Object))
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("still present: %v", err)
	}
}

// freePort is a localhost TCP port nothing listens on, for a server that
// must be given its port.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	return port, l.Close()
}

// poll calls f until it returns nil or timeout passes, at least once, and
// returns its last error.
func poll(timeout time.Duration, f func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := f()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}
