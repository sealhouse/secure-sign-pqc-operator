package operator

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
)

// startupPollMax caps LoadTuning's wait between reads.
const startupPollMax = 2 * time.Second

// LoadTuning reads the tuning ConfigMap and applies it to env.
func LoadTuning(ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme, namespace string, env tuning.Settings) (tuning.Settings, error) {
	log := logf.FromContext(ctx)
	c, err := client.New(RestConfig(cfg, tuning.NewLive(env)), client.Options{Scheme: scheme})
	if err != nil {
		return tuning.Settings{}, err
	}
	var cm corev1.ConfigMap
	ceiling := min(env.BackoffMax, startupPollMax)
	for delay := min(env.BackoffBase, ceiling); ; delay = min(2*delay, ceiling) {
		err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: tuning.ConfigMapName}, &cm)
		if err == nil {
			break
		}
		if apierrors.IsNotFound(err) {
			cm.Data = nil
			break
		}
		log.Info("Waiting for the API server to read tuning ConfigMap", "error", err.Error(), "retry", delay)
		select {
		case <-ctx.Done():
			return tuning.Settings{}, ctx.Err()
		case <-time.After(delay):
		}
	}
	if cm.Data == nil {
		return env, nil
	}
	s, err := tuning.WithConfigMap(env, cm.Data)
	if err != nil {
		log.Error(err, "Ignoring invalid tuning ConfigMap")
		return env, nil
	}
	return s, nil
}
