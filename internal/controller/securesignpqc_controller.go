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

package controller

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/tuning"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
)

// SecureSignPQCReconciler reconciles a SecureSignPQC object
type SecureSignPQCReconciler struct {
	client.Client
	// APIReader reads straight from the API server.
	APIReader client.Reader
	Recorder  events.EventRecorder
	Profiles  versions.Set
	// Settings are read on each use, so a ConcurrentReconciles change
	// needs a new controller and the rest apply at once.
	Settings *tuning.Live
	// Failures counts failed reconciles by reason; nil counts nothing.
	Failures *prometheus.CounterVec

	mu sync.Mutex
	// consecutiveFailures counts each instance's failed passes since its
	// last success, for Degraded. It is not the queue's requeue count,
	// which drives the backoff: a conflict is requeued but is no failure,
	// and an invalid signer Secret stays Degraded with no requeue.
	consecutiveFailures map[types.NamespacedName]int
}

// +kubebuilder:rbac:groups=pqc.rhtas.redhat.com,resources=securesignpqcs,verbs=get;list;watch
// +kubebuilder:rbac:groups=pqc.rhtas.redhat.com,resources=securesignpqcs/status,verbs=get;patch
// +kubebuilder:rbac:groups=pqc.rhtas.redhat.com,resources=securesignpqcs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile converges one SecureSignPQC on the profile for its spec.version.
func (r *SecureSignPQCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Read from the API server: status is applied whole, so a stale read would
	// overwrite newer values.
	var cr pqcv1alpha1.SecureSignPQC
	if err := r.APIReader.Get(ctx, req.NamespacedName, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			r.resetFailures(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		cr.Namespace, cr.Name = req.Namespace, req.Name
		r.recordFailure(ctx, &cr, err)
		return ctrl.Result{}, err
	}
	if !cr.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	orig := cr.DeepCopy()

	profile, ok := r.Profiles.Lookup(cr.Spec.Version)
	if !ok {
		r.setBlocked(&cr, "UnsupportedVersion", fmt.Sprintf("this operator does not support version %q; supported: %v", cr.Spec.Version, r.Profiles.Versions()))
		return ctrl.Result{}, r.applyStatus(ctx, orig, &cr)
	}
	if cr.Status.Version != "" && !r.Profiles.CanMove(cr.Status.Version, cr.Spec.Version) {
		r.setBlocked(&cr, "UnsupportedTransition", fmt.Sprintf("cannot move from version %s to %s; move one version at a time", cr.Status.Version, cr.Spec.Version))
		return ctrl.Result{}, r.applyStatus(ctx, orig, &cr)
	}

	ready := true
	var err error
	if profile.Has(versions.CapabilityTSA) {
		var ro rollout
		ro, err = r.reconcileTSA(ctx, &cr, profile)
		tsaReady := ro.available
		if err == nil {
			setComponent(&cr, pqcv1alpha1.ConditionTSAReady, ro, "timestamp authority")
			if tsaReady {
				cr.Status.TSA.URL = TSAURL(&cr)
			}
			ready = ready && tsaReady
			err = r.reconcileTSAIngress(ctx, &cr, tsaReady)
		}
	}

	if blocked, ok := errors.AsType[*blockedError](err); ok {
		r.setBlocked(&cr, blocked.reason, blocked.msg)
		return ctrl.Result{}, r.applyStatus(ctx, orig, &cr)
	}
	if err != nil {
		r.recordFailure(ctx, &cr, err)
		if serr := r.applyStatus(ctx, orig, &cr); serr != nil {
			log.Error(serr, "status update after reconcile failure")
		}
		if _, ok := errors.AsType[*invalidSignerError](err); ok {
			// Retrying cannot fix a bad Secret; its watch event requeues
			// this instance once someone does.
			log.Error(err, "signer secret unusable")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	r.setSucceeded(&cr)
	if ready {
		cr.Status.Version = cr.Spec.Version
		setCondition(&cr, metav1.Condition{
			Type: pqcv1alpha1.ConditionReady, Status: metav1.ConditionTrue,
			Reason: "AllComponentsReady", Message: "version " + cr.Spec.Version + " is running",
		})
	} else {
		setCondition(&cr, metav1.Condition{
			Type: pqcv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
			Reason: "ComponentsProgressing", Message: "waiting for components to become available",
		})
	}
	cr.Status.ObservedGeneration = cr.Generation
	return ctrl.Result{}, r.applyStatus(ctx, orig, &cr)
}

// setCondition sets c on cr, observed at cr's current generation, so a
// client can tell it from one an earlier spec left.
func setCondition(cr *pqcv1alpha1.SecureSignPQC, c metav1.Condition) {
	c.ObservedGeneration = cr.Generation
	meta.SetStatusCondition(&cr.Status.Conditions, c)
}

func setComponent(cr *pqcv1alpha1.SecureSignPQC, condType string, ro rollout, what string) {
	c := metav1.Condition{Type: condType}
	switch {
	case ro.available:
		c.Status, c.Reason, c.Message = metav1.ConditionTrue, "Available", what+" is available"
	case ro.reason != "":
		c.Status, c.Reason, c.Message = metav1.ConditionFalse, ro.reason, what+" cannot roll out: "+ro.message
	default:
		c.Status, c.Reason, c.Message = metav1.ConditionFalse, "Progressing", what+" is rolling out"
	}
	setCondition(cr, c)
}

// setSucceeded ends a run of failures.
func (r *SecureSignPQCReconciler) setSucceeded(cr *pqcv1alpha1.SecureSignPQC) {
	r.resetFailures(client.ObjectKeyFromObject(cr))
	setCondition(cr, metav1.Condition{
		Type: pqcv1alpha1.ConditionDegraded, Status: metav1.ConditionFalse,
		Reason: "ReconcileSucceeded", Message: "last reconcile succeeded",
	})
}

// setBlocked records a spec the operator will not act on. Refusing it is a
// successful pass.
func (r *SecureSignPQCReconciler) setBlocked(cr *pqcv1alpha1.SecureSignPQC, reason, msg string) {
	r.setSucceeded(cr)
	setCondition(cr, metav1.Condition{
		Type: pqcv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
		Reason: reason, Message: msg,
	})
	cr.Status.ObservedGeneration = cr.Generation
}

// applyStatus applies cr's whole status, if it changed, and only to the
// object it was computed from: the status subresource ignores the UID, so
// without the resourceVersion a pass that read an instance since deleted
// would write its status onto one recreated under the same name. A
// conflict is retried after a fresh read.
func (r *SecureSignPQCReconciler) applyStatus(ctx context.Context, orig, cr *pqcv1alpha1.SecureSignPQC) error {
	if equality.Semantic.DeepEqual(orig.Status, cr.Status) {
		return nil
	}
	status, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&cr.Status)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: map[string]any{"status": status}}
	u.SetGroupVersionKind(pqcv1alpha1.GroupVersion.WithKind("SecureSignPQC"))
	u.SetNamespace(cr.Namespace)
	u.SetName(cr.Name)
	u.SetUID(cr.UID)
	u.SetResourceVersion(cr.ResourceVersion)
	if err := r.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(u), client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		return err
	}
	// A later apply in the same pass builds on this write.
	cr.ResourceVersion = u.GetResourceVersion()
	return nil
}

// FailureReasons is every value failureReason returns, so the failure
// metric's reason label has a fixed set of values.
var FailureReasons = []string{"InvalidSigner", "Conflict", "Forbidden", "TooManyRequests", "ServiceUnavailable", "Timeout", "InternalError", "ReconcileError"}

// NewFailureCounter returns the pqc_operator_reconcile_failures_total
// counter, with every reason present at zero.
func NewFailureCounter() *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pqc_operator_reconcile_failures_total",
		Help: "Failed SecureSignPQC reconciles by reason.",
	}, []string{"reason"})
	for _, r := range FailureReasons {
		c.WithLabelValues(r)
	}
	return c
}

// failureReason maps an error to the Degraded condition's reason and the
// failure metric's reason label.
func failureReason(err error) string {
	var invalid *invalidSignerError
	switch {
	case errors.As(err, &invalid):
		return "InvalidSigner"
	case apierrors.IsConflict(err):
		return "Conflict"
	case apierrors.IsForbidden(err):
		return "Forbidden"
	case apierrors.IsTooManyRequests(err):
		return "TooManyRequests"
	case apierrors.IsServiceUnavailable(err):
		return "ServiceUnavailable"
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), errors.Is(err, context.DeadlineExceeded):
		return "Timeout"
	case apierrors.IsInternalError(err):
		return "InternalError"
	}
	return "ReconcileError"
}

// recordFailure counts a failed pass.
func (r *SecureSignPQCReconciler) recordFailure(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, err error) {
	degradedAfter := r.Settings.Load().DegradedAfter
	reason := failureReason(err)
	if r.Failures != nil {
		r.Failures.WithLabelValues(reason).Inc()
	}
	if apierrors.IsConflict(err) {
		logf.FromContext(ctx).V(1).Info("conflict; retrying after a fresh read", "error", err.Error())
		return
	}
	key := client.ObjectKeyFromObject(cr)
	r.mu.Lock()
	if r.consecutiveFailures == nil {
		r.consecutiveFailures = map[types.NamespacedName]int{}
	}
	r.consecutiveFailures[key]++
	var invalid *invalidSignerError
	if errors.As(err, &invalid) && r.consecutiveFailures[key] < degradedAfter {
		// Not transient: no retry is coming, so report it at once.
		r.consecutiveFailures[key] = degradedAfter
	}
	n := r.consecutiveFailures[key]
	r.mu.Unlock()

	if n >= degradedAfter {
		setCondition(cr, metav1.Condition{
			Type: pqcv1alpha1.ConditionDegraded, Status: metav1.ConditionTrue,
			Reason: reason, Message: fmt.Sprintf("%d consecutive failures; last: %v", n, err),
		})
		if n == degradedAfter && r.Recorder != nil {
			r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, reason, "Reconcile", "%v", err)
		}
	}
}

func (r *SecureSignPQCReconciler) resetFailures(key types.NamespacedName) {
	r.mu.Lock()
	delete(r.consecutiveFailures, key)
	r.mu.Unlock()
}

// signerToInstance maps a TSA CA or signer Secret to its SecureSignPQC.
func signerToInstance(_ context.Context, obj client.Object) []reconcile.Request {
	labels := obj.GetLabels()
	name, ok := labels[LabelInstance]
	if role := labels[LabelKeyRole]; !ok || (role != RoleTSACA && role != RoleTSASigner) {
		return nil
	}
	return []reconcile.Request{{Namespace: obj.GetNamespace(), Name: name}}
}

// RateLimiter is the per-object exponential backoff, capped at
// backoff_max, combined with an overall token bucket. Each requeue uses the
// current settings.
func RateLimiter(l *tuning.Live) workqueue.TypedRateLimiter[reconcile.Request] {
	s := l.Load()
	return &rateLimiter{
		settings: l,
		failures: map[reconcile.Request]int{},
		bucket:   rate.NewLimiter(rate.Limit(s.QueueQPS), s.QueueBurst),
	}
}

type rateLimiter struct {
	settings *tuning.Live
	mu       sync.Mutex
	failures map[reconcile.Request]int
	bucket   *rate.Limiter
}

func (r *rateLimiter) When(item reconcile.Request) time.Duration {
	s := r.settings.Load()
	r.mu.Lock()
	exp := r.failures[item]
	r.failures[item] = exp + 1
	if r.bucket.Limit() != rate.Limit(s.QueueQPS) {
		r.bucket.SetLimit(rate.Limit(s.QueueQPS))
	}
	if r.bucket.Burst() != s.QueueBurst {
		r.bucket.SetBurst(s.QueueBurst)
	}
	r.mu.Unlock()
	backoff := s.BackoffMax
	if d := float64(s.BackoffBase) * math.Pow(2, float64(exp)); d < float64(s.BackoffMax) {
		backoff = time.Duration(d)
	}
	return max(backoff, r.bucket.Reserve().Delay())
}

func (r *rateLimiter) Forget(item reconcile.Request) {
	r.mu.Lock()
	delete(r.failures, item)
	r.mu.Unlock()
}

func (r *rateLimiter) NumRequeues(item reconcile.Request) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failures[item]
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecureSignPQCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pqcv1alpha1.SecureSignPQC{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&networkingv1.Ingress{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(signerToInstance)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.Settings.Load().ConcurrentReconciles,
			RateLimiter:             RateLimiter(r.Settings),
		}).
		Named("securesignpqc").
		Complete(r)
}
