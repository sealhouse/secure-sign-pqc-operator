//go:build resilience

package operator

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
)

// A crash at every write.
func TestResilienceCrashAtEveryWrite(t *testing.T) {
	writes, want, _ := crashInstall(t, "crash-base", 0, false)
	if len(writes) == 0 {
		t.Fatal("the uninterrupted install made no writes")
	}
	t.Logf("uninterrupted install: %d writes, objects %v", len(writes), want)
	for n := 1; n <= len(writes); n++ {
		for _, landed := range []bool{false, true} {
			name := fmt.Sprintf("crash-%d-before", n)
			if landed {
				name = fmt.Sprintf("crash-%d-after", n)
			}
			t.Run(name, func(t *testing.T) {
				// After the key Secrets the install makes rounds of apply,
				// apply, status, one per event that reaches it, and
				// coalesced events make fewer rounds: an install can end
				// before write n.
				for range 3 {
					got, objects, crashed := crashInstall(t, name, n, landed)
					if !crashed {
						t.Logf("install ended after %d writes, before write %d; retrying", len(got), n)
						continue
					}
					if !slices.Equal(objects, want) {
						t.Fatalf("objects %v, want %v", objects, want)
					}
					return
				}
				// A repeat of an earlier write is crashed at in its first
				// round; only a write the install may make is skipped.
				w := writes[n-1]
				if slices.ContainsFunc(writes[:n-1], w.same) {
					t.Skipf("no install reached write %d, %s, a repeat of an earlier write", n, w)
				}
				t.Fatalf("no install reached write %d, %s", n, w)
			})
		}
	}
}

// crashInstall installs the demo instance under a supervisor that crashes
// the operator at its nth write in the instance's namespace (never, for 0),
// after sending it if landed.
func crashInstall(t *testing.T, name string, n int, landed bool) ([]write, []string, bool) {
	t.Helper()
	opns := createNamespace(t, "op")
	ns := createNamespace(t, name)
	var count atomic.Int32
	var sup atomic.Pointer[supervisor]
	nth := func(w write) bool { return w.namespace == ns && int(count.Add(1)) == n }
	hooks := &writeHooks{}
	if landed {
		hooks.after = func(w write, err error) error {
			if nth(w) {
				sup.Load().crash()
				return errCrashed
			}
			return err
		}
	} else {
		hooks.before = func(w write) error {
			if nth(w) {
				sup.Load().crash()
				return errCrashed
			}
			return nil
		}
	}
	var log writeLog
	s := supervise(t, supervisorOptions{restCfg: cfg, namespace: opns, env: resilienceSettings(), hooks: hooks, log: &log})
	sup.Store(s)
	installReady(t, ns, time.Minute)
	// Let any write still due after Ready land before counting.
	time.Sleep(2 * time.Second)

	crashes := 0
	for _, e := range s.exitList() {
		if e.err != errCrashed {
			t.Fatalf("operator exited with %v", e.err)
		}
		crashes++
	}
	if crashes > 1 || (crashes == 0 && n > 0 && int(count.Load()) >= n) {
		t.Fatalf("%d crashes at write %d of %d", crashes, n, count.Load())
	}
	checkOneKeyPerRole(t, ns)
	// Every operator reconciles every namespace: this one must not run on
	// into the next install.
	s.stop()
	var writes []write
	for _, w := range log.snapshot() {
		if w.namespace == ns {
			writes = append(writes, w)
			if n == 0 {
				t.Logf("  %s", w)
			}
		}
	}
	return writes, slices.Sorted(maps.Keys(withoutHashes(readOperands(t, ns)))), crashes == 1
}

// withoutHashes keeps the object names of an operand state.
func withoutHashes(s operandState) operandState {
	out := operandState{}
	for k, v := range s {
		if k[len(k)-len("#signer-hash"):] != "#signer-hash" {
			out[k] = v
		}
	}
	return out
}

// checkOneKeyPerRole fails unless the instance's status names exactly the
// CA and signer that its Secrets hold, and its pods mount that signer.
func checkOneKeyPerRole(t *testing.T, ns string) {
	t.Helper()
	cr := getCR(t, ns)
	if got := signerStatus(cr); got != "1:ML-DSA-65:Active" {
		t.Fatalf("signers %s, want one active generation-1 key", got)
	}
	chain := decodeSigner(t, ns, 1)
	if got, want := cr.Status.TSA.Signers[0].SerialNumber, chain.Leaf.SerialNumber.Text(16); got != want {
		t.Fatalf("status names signer %s, the Secret holds %s", got, want)
	}
	if cr.Status.TSA.CA == nil || cr.Status.TSA.CA.SerialNumber != chain.Intermediate.SerialNumber.Text(16) {
		t.Fatalf("status CA %+v, the Secret holds %s", cr.Status.TSA.CA, chain.Intermediate.SerialNumber.Text(16))
	}
	var d appsv1.Deployment
	if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &d); err != nil {
		t.Fatal(err)
	}
	if got := d.Spec.Template.Spec.Volumes[0].Secret.SecretName; got != controller.TSASignerSecretName("demo", 1) {
		t.Fatalf("pods mount %s", got)
	}
	if !conditionIsTrue(cr, pqcv1alpha1.ConditionReady) {
		t.Fatal("not Ready")
	}
}

func conditionIsTrue(cr *pqcv1alpha1.SecureSignPQC, typ string) bool {
	return conditionIs(cr, typ, "True", "") == nil
}
