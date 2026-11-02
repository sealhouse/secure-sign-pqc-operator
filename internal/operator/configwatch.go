package operator

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
)

// configWatcher applies a valid change to the tuning ConfigMap: in place
// when every changed setting is live, or by restarting the manager. It
// records a Warning event on the ConfigMap when its contents are invalid.
type configWatcher struct {
	cache     cache.Cache
	namespace string
	env       tuning.Settings
	live      *tuning.Live
	metric    *prometheus.GaugeVec
	recorder  events.EventRecorder
	restart   func(tuning.Settings)

	once sync.Once
}

func (w *configWatcher) NeedLeaderElection() bool { return false }

func (w *configWatcher) Start(ctx context.Context) error {
	inf, err := w.cache.GetInformer(ctx, &corev1.ConfigMap{})
	if err != nil {
		return err
	}
	reg, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.check(ctx, obj, false) },
		UpdateFunc: func(_, obj any) { w.check(ctx, obj, false) },
		DeleteFunc: func(obj any) { w.check(ctx, obj, true) },
	})
	if err != nil {
		return err
	}
	<-ctx.Done()
	return inf.RemoveEventHandler(reg)
}

func (w *configWatcher) check(ctx context.Context, obj any, deleted bool) {
	if d, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj, deleted = d.Obj, true
	}
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Namespace != w.namespace || cm.Name != tuning.ConfigMapName {
		return
	}
	log := logf.FromContext(ctx).WithName("tuning")
	want := w.env
	if !deleted {
		s, err := tuning.WithConfigMap(w.env, cm.Data)
		if err != nil {
			log.Error(err, "ignoring invalid tuning ConfigMap; settings unchanged")
			w.recorder.Eventf(cm, nil, corev1.EventTypeWarning, "InvalidTuning", "Validate",
				"settings unchanged: %v", err)
			return
		}
		want = s
	}
	running := w.live.Load()
	if want == running {
		return
	}
	if keys := tuning.RestartNeeded(running, want); len(keys) > 0 {
		w.once.Do(func() {
			log.Info("tuning settings changed; restarting the manager", "settings", keys)
			w.restart(want)
		})
		return
	}
	w.live.Store(want)
	setConfigMetric(w.metric, want)
	log.Info("tuning settings applied", "settings", want.Values())
}
