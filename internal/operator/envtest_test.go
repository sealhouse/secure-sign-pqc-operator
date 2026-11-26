package operator

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// envtest starts etcd and kube-apiserver in their own process group with no
// parent-death signal, so they outlive a test binary that exits without
// stopping them: a terminal's interrupt never reaches them, and a timeout
// panic or a kill skips every cleanup.

// liveEnvs holds the API servers started and not yet stopped.
var liveEnvs struct {
	sync.Mutex
	envs map[*envtest.Environment]bool
}

// startEnv starts env, holding off a signal's stop until it is tracked.
func startEnv(env *envtest.Environment) (*rest.Config, error) {
	liveEnvs.Lock()
	defer liveEnvs.Unlock()
	if liveEnvs.envs == nil {
		liveEnvs.envs = map[*envtest.Environment]bool{}
	}
	liveEnvs.envs[env] = true
	return env.Start()
}

// stopEnv stops env and stops tracking it.
func stopEnv(env *envtest.Environment) error {
	liveEnvs.Lock()
	defer liveEnvs.Unlock()
	delete(liveEnvs.envs, env)
	return env.Stop()
}

// stopOnSignal stops the running API servers and the suite's processes when
// the test binary is interrupted or terminated.
func stopOnSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		s := <-sig
		fmt.Fprintf(os.Stderr, "%v: stopping the API servers\n", s)
		liveEnvs.Lock()
		for env := range liveEnvs.envs {
			if err := env.Stop(); err != nil {
				fmt.Fprintln(os.Stderr, "envtest stop:", err)
			}
		}
		liveEnvs.Unlock()
		for _, f := range suiteCleanups {
			f()
		}
		os.Exit(1)
	}()
}
