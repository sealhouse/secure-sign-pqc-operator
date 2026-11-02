package controller

import (
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
)

// The backoff doubles to backoff_max, and a settings change applies to the
// next requeue.
func TestRateLimiterFollowsSettings(t *testing.T) {
	s := tuning.Defaults()
	s.BackoffBase, s.BackoffMax = 10*time.Millisecond, 50*time.Millisecond
	s.QueueQPS, s.QueueBurst = 1000, 1000
	live := tuning.NewLive(s)
	rl := RateLimiter(live)
	item := reconcile.Request{Name: "demo"}
	got := make([]time.Duration, 0, 4)
	for range 4 {
		got = append(got, rl.When(item))
	}
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoffs %v, want %v", got, want)
		}
	}
	if n := rl.NumRequeues(item); n != 4 {
		t.Fatalf("%d requeues, want 4", n)
	}

	s.BackoffMax = 30 * time.Millisecond
	live.Store(s)
	if d := rl.When(item); d != 30*time.Millisecond {
		t.Fatalf("backoff %s after backoff_max became 30ms", d)
	}
	rl.Forget(item)
	if d := rl.When(item); d != 10*time.Millisecond {
		t.Fatalf("backoff %s after Forget, want backoff_base", d)
	}

	// One token a second, burst one: the second requeue of another item
	// waits for the bucket.
	s.QueueQPS, s.QueueBurst = 1, 1
	live.Store(s)
	rl.When(reconcile.Request{Name: "a"})
	if d := rl.When(reconcile.Request{Name: "b"}); d < 500*time.Millisecond {
		t.Fatalf("backoff %s with the queue bucket at 1/s", d)
	}
}
