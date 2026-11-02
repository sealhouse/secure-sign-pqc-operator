//go:build e2e && soak

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/timestamp-authority/v2/pkg/verification"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/operator"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
)

// The soak kills the operator at random for SOAK_DURATION (default 1h)
// while it reconciles an instance, and checks after every kill that it
// recovered within budget without touching the instance's keys or rolling
// its TSA.
const (
	soakInstance = "soak"
	soakLabel    = "soak.sealhouse.dev/tick"

	sampleEvery = 30 * time.Second
	workEvery   = 30 * time.Second
)

// recoveryBudget is the longest a kill mode may take to recover, from the
// kill to the instance verified again.
var recoveryBudget = map[string]time.Duration{
	"graceful": 2 * time.Minute,
	"force":    leaseDuration + 90*time.Second,
	"sigkill":  6 * time.Minute,
}

// sample is one scrape of the leader's metrics.
type sample struct {
	At         time.Time `json:"at"`
	Pod        string    `json:"pod"`
	Steady     bool      `json:"steady"`
	Goroutines float64   `json:"goroutines"`
	HeapInuse  float64   `json:"heapInuseBytes"`
	Sys        float64   `json:"sysBytes"`
	Failures   float64   `json:"reconcileFailures"`
}

// kill is one operator kill and its recovery.
type kill struct {
	Mode     string        `json:"mode"`
	Pod      string        `json:"pod"`
	Recovery time.Duration `json:"recoveryNs"`
}

// soakSummary is what SOAK_OUT receives.
type soakSummary struct {
	OperatorImage string        `json:"operatorImage"`
	CSV           string        `json:"csv"`
	Seed          uint64        `json:"seed"`
	Duration      time.Duration `json:"durationNs"`
	Steady        time.Duration `json:"steadyNs"`
	Kills         []kill        `json:"kills"`
	// Steady-phase medians over its last samples, the values the trend keeps.
	Goroutines float64  `json:"goroutines"`
	HeapInuse  float64  `json:"heapInuseBytes"`
	Sys        float64  `json:"sysBytes"`
	Samples    []sample `json:"samples"`
	Errors     []string `json:"errors"`
}

func TestSoak(t *testing.T) {
	ctx := t.Context()
	duration := envDuration(t, "SOAK_DURATION", time.Hour)
	steady := envDuration(t, "SOAK_STEADY", 20*time.Minute)
	seed := uint64(time.Now().UnixNano())
	if s := os.Getenv("SOAK_SEED"); s != "" {
		var err error
		if seed, err = strconv.ParseUint(s, 10, 64); err != nil {
			t.Fatalf("SOAK_SEED: %v", err)
		}
	}
	rng := mrand.New(mrand.NewPCG(seed, seed))
	t.Logf("soak: %s of kills, %s steady, SOAK_SEED=%d", duration, steady, seed)

	cr := &pqcv1alpha1.SecureSignPQC{
		Namespace: namespace, Name: soakInstance,
		Spec: pqcv1alpha1.SecureSignPQCSpec{
			Version: "2.0",
			TSA:     pqcv1alpha1.TSASpec{Signing: pqcv1alpha1.SigningSpec{Algorithm: pqcv1alpha1.MLDSA65}},
		},
	}
	deleteInstance(t, cr)
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteInstance(t, cr) })
	if err := waitReady(ctx, cr); err != nil {
		t.Fatalf("instance not Ready: %v", err)
	}
	s := &soak{t: t, cr: cr, rng: rng}
	var err error
	if s.keys, err = keySecrets(ctx, client.ObjectKeyFromObject(cr)); err != nil {
		t.Fatal(err)
	}
	if len(s.keys) == 0 {
		t.Fatal("instance has no key Secrets")
	}
	if s.tsaGeneration, s.tsaPods, err = tsaRollout(ctx, cr); err != nil {
		t.Fatal(err)
	}
	if err := s.verify(ctx); err != nil {
		t.Fatalf("before the first kill: %v", err)
	}
	token, err := metricsToken(ctx)
	if err != nil {
		t.Fatal(err)
	}

	sampling, stopSampling := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() { s.sample(sampling, token) })

	// Kills, each followed by a stretch of workload; the interval scales
	// with the duration (2 to 6 minutes for an hour).
	minGap, maxGap := duration/30, duration/10
	end := time.Now().Add(duration)
	for time.Now().Before(end) && !t.Failed() {
		s.work(ctx, minGap+time.Duration(rng.Int64N(int64(maxGap-minGap)+1)))
		mode := []string{"graceful", "force", "sigkill"}[rng.IntN(3)]
		if mode == "sigkill" && openshift {
			mode = "force"
		}
		s.kill(ctx, mode)
	}

	s.mu.Lock()
	s.steadyFrom = time.Now()
	s.mu.Unlock()
	t.Logf("steady phase: %s with no kills", steady)
	s.work(ctx, steady)
	stopSampling()
	wg.Wait()

	s.analyse(duration, steady, seed)
}

type soak struct {
	t   *testing.T
	cr  *pqcv1alpha1.SecureSignPQC
	rng *mrand.Rand

	keys          map[string]types.UID
	tsaGeneration int64
	tsaPods       []types.UID

	mu         sync.Mutex
	steadyFrom time.Time
	samples    []sample
	kills      []kill
	errors     []string
}

// fail records a failure for the summary and the test.
func (s *soak) fail(format string, args ...any) {
	s.t.Helper()
	msg := fmt.Sprintf(format, args...)
	s.mu.Lock()
	s.errors = append(s.errors, msg)
	s.mu.Unlock()
	s.t.Error(msg)
}

// work keeps the operator reconciling for d: a label change on the instance
// every workEvery, and once per stretch a deleted TSA Service the operator
// must recreate, then a verified timestamp.
func (s *soak) work(ctx context.Context, d time.Duration) {
	end := time.Now().Add(d)
	deleteAt := time.Now().Add(time.Duration(s.rng.Int64N(int64(d/2) + 1)))
	deleted := false
	for time.Now().Before(end) && !s.t.Failed() {
		if err := s.tick(ctx); err != nil {
			s.fail("label tick: %v", err)
			return
		}
		if !deleted && time.Now().After(deleteAt) {
			deleted = true
			if err := s.repairService(ctx); err != nil {
				s.fail("TSA Service: %v", err)
				return
			}
			if err := s.verify(ctx); err != nil {
				s.fail("after the Service was recreated: %v", err)
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(workEvery, time.Until(end))):
		}
	}
}

func (s *soak) tick(ctx context.Context) error {
	return createOrUpdate(ctx, s.cr, func() {
		if s.cr.Labels == nil {
			s.cr.Labels = map[string]string{}
		}
		s.cr.Labels[soakLabel] = strconv.FormatInt(time.Now().Unix(), 10)
	})
}

// repairService deletes the TSA Service and waits for the operator to make
// it again.
func (s *soak) repairService(ctx context.Context) error {
	key := client.ObjectKey{Namespace: namespace, Name: controller.TSAName(s.cr.Name)}
	var svc corev1.Service
	if err := k8s.Get(ctx, key, &svc); err != nil {
		return err
	}
	old := svc.UID
	if err := k8s.Delete(ctx, &svc); err != nil {
		return err
	}
	return poll(ctx, 2*time.Minute, func() (bool, error) {
		err := k8s.Get(ctx, key, &svc)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil && svc.UID != old, err
	})
}

// kill kills the leader one way and waits for the operator to recover.
func (s *soak) kill(ctx context.Context, mode string) {
	s.t.Helper()
	pod, err := leader(ctx)
	if err != nil {
		s.fail("before a %s kill: %v", mode, err)
		return
	}
	start := time.Now()
	switch mode {
	case "graceful", "force":
		p := &corev1.Pod{Namespace: operatorNamespace, Name: pod}
		var opts []client.DeleteOption
		if mode == "force" {
			opts = append(opts, client.GracePeriodSeconds(0))
		}
		if err := k8s.Delete(ctx, p, opts...); err != nil {
			s.fail("%s delete of %s: %v", mode, pod, err)
			return
		}
		if _, _, err := handover(ctx, []string{pod}); err != nil {
			s.fail("%s kill of %s: %v", mode, pod, err)
			return
		}
	case "sigkill":
		if err := sigkill(ctx, pod); err != nil {
			s.fail("sigkill of %s: %v", pod, err)
			return
		}
	}
	if err := waitReady(ctx, s.cr); err != nil {
		s.fail("after a %s kill of %s: instance not Ready: %v", mode, pod, err)
		return
	}
	if err := s.verify(ctx); err != nil {
		s.fail("after a %s kill of %s: %v", mode, pod, err)
		return
	}
	took := time.Since(start)
	s.mu.Lock()
	s.kills = append(s.kills, kill{Mode: mode, Pod: pod, Recovery: took})
	s.mu.Unlock()
	s.t.Logf("%s kill of %s: recovered in %s", mode, pod, took.Round(time.Second))
	if took > recoveryBudget[mode] {
		s.fail("%s kill of %s took %s to recover, budget %s", mode, pod, took.Round(time.Second), recoveryBudget[mode])
	}
}

// verify checks that the instance kept its keys and its TSA rollout, and
// that the TSA answers with a timestamp that verifies.
func (s *soak) verify(ctx context.Context) error {
	keys, err := keySecrets(ctx, client.ObjectKeyFromObject(s.cr))
	if err != nil {
		return err
	}
	if !maps.Equal(keys, s.keys) {
		return fmt.Errorf("key Secrets changed: %v, were %v", keys, s.keys)
	}
	gen, pods, err := tsaRollout(ctx, s.cr)
	if err != nil {
		return err
	}
	if gen != s.tsaGeneration || !slices.Equal(pods, s.tsaPods) {
		return fmt.Errorf("TSA rolled out: generation %d pods %v, were %d %v", gen, pods, s.tsaGeneration, s.tsaPods)
	}
	return verifiedTimestamp(ctx, s.cr)
}

// sample scrapes the leader every sampleEvery until ctx ends.
func (s *soak) sample(ctx context.Context, token string) {
	for {
		pod, err := leader(ctx)
		if err == nil {
			var m map[string]float64
			if m, err = scrape(ctx, pod, token); err == nil {
				s.mu.Lock()
				s.samples = append(s.samples, sample{
					At: time.Now(), Pod: pod, Steady: !s.steadyFrom.IsZero(),
					Goroutines: m["go_goroutines"], HeapInuse: m["go_memstats_heap_inuse_bytes"],
					Sys: m["go_memstats_sys_bytes"], Failures: m["pqc_operator_reconcile_failures_total"],
				})
				s.mu.Unlock()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sampleEvery):
		}
	}
}

// analyse checks the steady phase and writes the summary.
func (s *soak) analyse(duration, steady time.Duration, seed uint64) {
	s.t.Helper()
	warm := s.steadyFrom.Add(min(steady/4, 5*time.Minute))
	var steadySamples []sample
	for _, x := range s.samples {
		if x.Steady && x.At.After(warm) {
			steadySamples = append(steadySamples, x)
		}
	}
	const window = 4
	sum := soakSummary{
		OperatorImage: published.OperatorImage, CSV: published.CSV, Seed: seed,
		Duration: duration, Steady: steady, Kills: s.kills, Samples: s.samples,
	}
	if len(steadySamples) < 2*window {
		s.fail("steady phase has %d samples after warm-up, want at least %d", len(steadySamples), 2*window)
	} else {
		first, last := steadySamples[:window], steadySamples[len(steadySamples)-window:]
		for _, x := range steadySamples[1:] {
			if x.Pod != steadySamples[0].Pod {
				s.fail("steady phase spans operator pods %s and %s", steadySamples[0].Pod, x.Pod)
				break
			}
		}
		goroutines := func(x sample) float64 { return x.Goroutines }
		heap := func(x sample) float64 { return x.HeapInuse }
		g0, g1 := median(first, goroutines), median(last, goroutines)
		h0, h1 := median(first, heap), median(last, heap)
		sum.Goroutines, sum.HeapInuse = g1, h1
		sum.Sys = median(last, func(x sample) float64 { return x.Sys })
		s.t.Logf("steady phase: goroutines %.0f -> %.0f, heap in use %.1f -> %.1f MiB",
			g0, g1, h0/(1<<20), h1/(1<<20))
		if g1 > max(g0*1.1, g0+5) {
			s.fail("goroutines grew from %.0f to %.0f in the steady phase", g0, g1)
		}
		if h1 > h0*1.5 {
			s.fail("heap in use grew from %.1f to %.1f MiB in the steady phase", h0/(1<<20), h1/(1<<20))
		}
		if f0, f1 := steadySamples[0].Failures, steadySamples[len(steadySamples)-1].Failures; f1 > f0 {
			s.fail("%.0f reconciles failed in the steady phase", f1-f0)
		}
	}
	sum.Errors = s.errors
	if out := os.Getenv("SOAK_OUT"); out != "" {
		b, err := json.MarshalIndent(sum, "", "  ")
		if err == nil {
			err = os.WriteFile(out, b, 0o644)
		}
		if err != nil {
			s.t.Errorf("SOAK_OUT: %v", err)
		}
	}
}

func median(xs []sample, f func(sample) float64) float64 {
	v := make([]float64, 0, len(xs))
	for _, x := range xs {
		v = append(v, f(x))
	}
	slices.Sort(v)
	if n := len(v); n%2 == 0 {
		return (v[n/2-1] + v[n/2]) / 2
	}
	return v[len(v)/2]
}

func envDuration(t *testing.T, key string, def time.Duration) time.Duration {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		t.Fatalf("%s=%q is not a positive duration", key, v)
	}
	return d
}

// leaseKey is the operator's leader lease.
var leaseKey = client.ObjectKey{Namespace: operatorNamespace, Name: operator.LeaderElectionID}

// leader names the pod that holds the operator's leader lease.
func leader(ctx context.Context) (string, error) {
	lease := &coordinationv1.Lease{}
	if err := k8s.Get(ctx, leaseKey, lease); err != nil {
		return "", err
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return "", fmt.Errorf("lease %s has no holder", operator.LeaderElectionID)
	}
	return *lease.Spec.HolderIdentity, nil
}

// tsaRollout returns the TSA Deployment's generation and its pods' UIDs,
// sorted: an operator restart that rolls the operand changes either.
func tsaRollout(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) (int64, []types.UID, error) {
	var d appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: cr.Namespace, Name: controller.TSAName(cr.Name)}, &d); err != nil {
		return 0, nil, err
	}
	var pods corev1.PodList
	if err := k8s.List(ctx, &pods, client.InNamespace(cr.Namespace),
		client.MatchingLabels(d.Spec.Selector.MatchLabels)); err != nil {
		return 0, nil, err
	}
	uids := make([]types.UID, 0, len(pods.Items))
	for _, p := range pods.Items {
		uids = append(uids, p.UID)
	}
	slices.Sort(uids)
	return d.Generation, uids, nil
}

// sigkill kills the operator container of pod from its kind node, the way an
// OOM kill or a crash ends it, and waits for the restarted process to renew
// the lease it still holds.
func sigkill(ctx context.Context, pod string) error {
	var p corev1.Pod
	key := client.ObjectKey{Namespace: operatorNamespace, Name: pod}
	if err := k8s.Get(ctx, key, &p); err != nil {
		return err
	}
	if len(p.Status.ContainerStatuses) != 1 {
		return fmt.Errorf("pod %s has %d containers", pod, len(p.Status.ContainerStatuses))
	}
	restarts := p.Status.ContainerStatuses[0].RestartCount
	id, ok := strings.CutPrefix(p.Status.ContainerStatuses[0].ContainerID, "containerd://")
	if !ok {
		return fmt.Errorf("pod %s container ID %q is not containerd's", pod, p.Status.ContainerStatuses[0].ContainerID)
	}
	// The kind node's container is named after the node.
	if out, err := exec.CommandContext(ctx, "docker", "exec", p.Spec.NodeName,
		"crictl", "stop", "--timeout", "0", id).CombinedOutput(); err != nil {
		return fmt.Errorf("crictl stop on %s: %w: %s", p.Spec.NodeName, err, out)
	}
	var started time.Time
	if err := pollEvery(ctx, time.Second, recoveryBudget["sigkill"], func() (bool, error) {
		if err := k8s.Get(ctx, key, &p); err != nil {
			return false, err
		}
		cs := p.Status.ContainerStatuses[0]
		if cs.RestartCount == restarts || !cs.Ready || cs.State.Running == nil {
			return false, nil
		}
		started = cs.State.Running.StartedAt.Time
		return true, nil
	}); err != nil {
		return fmt.Errorf("container did not restart: %w", err)
	}
	lease := &coordinationv1.Lease{}
	return pollEvery(ctx, time.Second, leaseDuration, func() (bool, error) {
		if err := k8s.Get(ctx, leaseKey, lease); err != nil {
			return false, err
		}
		return lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == pod &&
			lease.Spec.RenewTime != nil && !lease.Spec.RenewTime.Time.Before(started), nil
	})
}

// verifiedTimestamp asks the instance's TSA for a timestamp and verifies it
// against the instance's trust anchor.
func verifiedTimestamp(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) error {
	var ca corev1.Secret
	caKey := client.ObjectKey{Namespace: cr.Namespace, Name: controller.TSACASecretName(cr.Name)}
	if err := k8s.Get(ctx, caKey, &ca); err != nil {
		return err
	}
	root, err := pemCertificate(ca.Data[pki.RootPEM])
	if err != nil {
		return err
	}
	intermediate, err := pemCertificate(ca.Data[pki.IntermediatePEM])
	if err != nil {
		return err
	}
	artifact := []byte("sealhouse soak " + time.Now().UTC().Format(time.RFC3339Nano))
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return err
	}
	req, err := timestamp.CreateRequest(bytes.NewReader(artifact), &timestamp.RequestOptions{
		Hash: crypto.SHA256, Certificates: true, Nonce: nonce,
	})
	if err != nil {
		return err
	}
	tsr, err := requestTimestamp(ctx, controller.TSAName(cr.Name), req)
	if err != nil {
		return err
	}
	_, err = verification.VerifyTimestampResponse(tsr, bytes.NewReader(artifact), verification.VerifyOpts{
		Roots: []*x509.Certificate{root}, Intermediates: []*x509.Certificate{intermediate}, Nonce: nonce,
	})
	return err
}

// metricsToken returns a token the operator's metrics endpoint accepts: the
// bundle's metrics-scraper account's, as Prometheus presents it.
func metricsToken(ctx context.Context) (string, error) {
	expiry := int64((3 * time.Hour).Seconds())
	tr, err := clientset.CoreV1().ServiceAccounts(operatorNamespace).CreateToken(ctx, metricsScraper,
		&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiry}},
		metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return tr.Status.Token, nil
}

// scrape reads the operator pod's metrics through a port-forward to its
// :8443. The API server's pod proxy would not pass the bearer token on, and
// the endpoint authenticates every request.
func scrape(ctx context.Context, pod, token string) (map[string]float64, error) {
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return nil, err
	}
	url := clientset.CoreV1().RESTClient().Post().
		Namespace(operatorNamespace).Resource("pods").Name(pod).SubResource("portforward").URL()
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)
	stop, ready := make(chan struct{}), make(chan struct{})
	pf, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{"0:8443"},
		stop, ready, io.Discard, io.Discard)
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- pf.ForwardPorts() }()
	defer close(stop)
	select {
	case <-ready:
	case err := <-done:
		return nil, fmt.Errorf("port-forward to %s: %w", pod, err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ports, err := pf.GetPorts()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://127.0.0.1:%d/metrics", ports[0].Local), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// The operator serves metrics with a self-signed certificate; the
	// bearer token, not the certificate, is what is under test.
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed metrics certificate
	}}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics from %s: HTTP %d", pod, res.StatusCode)
	}
	return parseMetrics(res.Body)
}

// parseMetrics sums each metric's samples over their labels, from the
// Prometheus text format.
func parseMetrics(r io.Reader) (map[string]float64, error) {
	m := map[string]float64{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		before, after, ok := strings.CutLast(line, " ")
		if !ok {
			continue
		}
		name := before
		if j := strings.IndexByte(name, '{'); j >= 0 {
			name = name[:j]
		}
		v, err := strconv.ParseFloat(after, 64)
		if err != nil {
			continue
		}
		m[name] += v
	}
	return m, sc.Err()
}
