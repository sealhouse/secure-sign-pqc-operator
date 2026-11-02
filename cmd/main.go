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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	// Client auth plugins, for running outside a cluster.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/operator"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))

	utilruntime.Must(pqcv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics server")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// HTTP/2 stays off unless asked for (Rapid Reset, GHSA-qppj-fm5r-hxr3).
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// Scrapers authenticate with a token that may get /metrics, as the
		// metrics-scraper account's may.
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	metricsOptions := operator.MetricsOptions{Secure: secureMetrics}
	if metricsAddr != "0" {
		metricsOptions.Service = os.Getenv("METRICS_SERVICE")
		metricsOptions.Scraper = os.Getenv("METRICS_SCRAPER")
	}
	// The operator serves the certificate once it is mounted, and a
	// self-signed one until then or without one.
	if len(metricsCertPath) > 0 {
		metricsOptions.CertFile = filepath.Join(metricsCertPath, metricsCertName)
		metricsOptions.KeyFile = filepath.Join(metricsCertPath, metricsCertKey)
	}

	namespace := os.Getenv("OPERATOR_NAMESPACE")
	if namespace == "" {
		setupLog.Error(nil, "OPERATOR_NAMESPACE must be set to the operator's namespace")
		os.Exit(1)
	}
	envSettings, err := tuning.FromEnv(os.LookupEnv)
	if err != nil {
		setupLog.Error(err, "Invalid tuning environment")
		os.Exit(1)
	}
	profiles, err := supported.Load()
	if err != nil {
		setupLog.Error(err, "Failed to load version profiles")
		os.Exit(1)
	}
	overridden, err := profiles.Override(os.LookupEnv)
	if err != nil {
		setupLog.Error(err, "Invalid operand image in the environment")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	cfg := ctrl.GetConfigOrDie()
	effective, err := loadTuning(ctx, cfg, namespace, envSettings, probeAddr)
	if err != nil {
		setupLog.Error(err, "Failed to read tuning ConfigMap")
		os.Exit(1)
	}
	setupLog.Info("Effective tuning", "settings", effective.Values(), "versions", profiles.Versions(),
		"imagesFromEnv", overridden)

	err = operator.Run(ctx, cfg, operator.Options{
		Scheme:    scheme,
		Namespace: namespace,
		Env:       envSettings,
		Effective: effective,
		Profiles:  profiles,
		Manager: ctrl.Options{
			Metrics:                metricsServerOptions,
			HealthProbeBindAddress: probeAddr,
		},
		Metrics:        metricsOptions,
		LeaderElection: enableLeaderElection,
		// The Deployment sets POD_NAME from the downward API.
		LeaderElectionIdentity: os.Getenv("POD_NAME"),
	})
	if err != nil {
		setupLog.Error(err, "Operator stopped")
		os.Exit(1)
	}
}

// loadTuning runs operator.LoadTuning while serving /healthz, so an API
// outage at startup does not fail the liveness probe.
func loadTuning(
	ctx context.Context, cfg *rest.Config, namespace string, env tuning.Settings, probeAddr string,
) (tuning.Settings, error) {
	stop := serveHealthz(probeAddr)
	defer stop()
	return operator.LoadTuning(ctrl.LoggerInto(ctx, setupLog), cfg, scheme, namespace, env)
}

// serveHealthz answers liveness probes until the manager's own probe server
// takes over the address.
func serveHealthz(addr string) func() {
	if addr == "" || addr == "0" {
		return func() {}
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Addr: addr, ReadHeaderTimeout: 5 * time.Second, Handler: ok}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		setupLog.Error(err, "Startup health endpoint unavailable")
		return func() {}
	}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}
