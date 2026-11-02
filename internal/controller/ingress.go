package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	networkingv1ac "k8s.io/client-go/applyconfigurations/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// routeTerminationAnnotation asks OpenShift's ingress-to-route controller
// for a Route that terminates TLS at the router.
const routeTerminationAnnotation = "route.openshift.io/termination"

var (
	routeGK         = schema.GroupKind{Group: "route.openshift.io", Kind: "Route"}
	clusterIngressV = schema.GroupVersionKind{Group: "config.openshift.io", Version: "v1", Kind: "Ingress"}
)

// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups=config.openshift.io,resources=ingresses,verbs=get

// servesRoutes reports whether the cluster has OpenShift Routes.
func (r *SecureSignPQCReconciler) servesRoutes() (bool, error) {
	_, err := r.RESTMapper().RESTMapping(routeGK)
	if meta.IsNoMatchError(err) {
		return false, nil
	}
	return err == nil, err
}

// clusterDomain is the OpenShift cluster's ingress domain, or "" without one.
func (r *SecureSignPQCReconciler) clusterDomain(ctx context.Context) (string, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(clusterIngressV)
	switch err := r.APIReader.Get(ctx, types.NamespacedName{Name: "cluster"}, u); {
	case meta.IsNoMatchError(err), apierrors.IsNotFound(err):
		return "", nil
	case err != nil:
		return "", err
	}
	domain, _, err := unstructured.NestedString(u.Object, "spec", "domain")
	return domain, err
}

// tsaIngressHost is spec.tsa.ingress.host, or on OpenShift
// <service>-<namespace>.<cluster domain>.
func (r *SecureSignPQCReconciler) tsaIngressHost(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, openshift bool) (string, error) {
	if h := cr.Spec.TSA.Ingress.Host; h != "" {
		return h, nil
	}
	if openshift {
		domain, err := r.clusterDomain(ctx)
		if err != nil {
			return "", err
		}
		if domain != "" {
			label := TSAName(cr.Name) + "-" + cr.Namespace
			host := label + "." + domain
			if len(validation.IsDNS1123Label(label)) > 0 || len(validation.IsDNS1123Subdomain(host)) > 0 {
				return "", &blockedError{
					reason: "IngressHostTooLong",
					msg:    fmt.Sprintf("the default host %s is not a valid DNS name; set spec.tsa.ingress.host", host),
				}
			}
			return host, nil
		}
	}
	return "", &blockedError{
		reason: "IngressHostRequired",
		msg:    "spec.tsa.ingress.host is required: the cluster has no OpenShift ingress domain",
	}
}

func tsaIngress(cr *pqcv1alpha1.SecureSignPQC, host string, openshift bool) *networkingv1ac.IngressApplyConfiguration {
	labels := maps.Clone(cr.Spec.TSA.Ingress.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	maps.Copy(labels, tsaLabels(cr))
	spec := networkingv1ac.IngressSpec().
		WithRules(networkingv1ac.IngressRule().
			WithHost(host).
			WithHTTP(networkingv1ac.HTTPIngressRuleValue().
				WithPaths(networkingv1ac.HTTPIngressPath().
					WithPath("/").
					WithPathType(networkingv1.PathTypePrefix).
					WithBackend(networkingv1ac.IngressBackend().
						WithService(networkingv1ac.IngressServiceBackend().
							WithName(TSAName(cr.Name)).
							WithPort(networkingv1ac.ServiceBackendPort().WithName("http")))))))
	ing := networkingv1ac.Ingress(TSAName(cr.Name), cr.Namespace).
		WithLabels(labels).
		WithOwnerReferences(ownerReference(cr))
	if openshift {
		// The router's default certificate serves the Route.
		ing.WithAnnotations(map[string]string{routeTerminationAnnotation: "edge"})
		spec.WithTLS(networkingv1ac.IngressTLS())
	}
	return ing.WithSpec(spec)
}

// reconcileTSAIngress applies the TSA Ingress if spec.tsa.ingress is
// enabled and sets the TSAIngressReady condition. A spec it cannot act on
// is reported in the condition, not returned, so it never holds up the TSA.
func (r *SecureSignPQCReconciler) reconcileTSAIngress(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, tsaAvailable bool) error {
	if !cr.Spec.TSA.Ingress.Enabled {
		meta.RemoveStatusCondition(&cr.Status.Conditions, pqcv1alpha1.ConditionTSAIngressReady)
		cr.Status.TSA.ExternalURL = ""
		return nil
	}
	c := metav1.Condition{Type: pqcv1alpha1.ConditionTSAIngressReady, Status: metav1.ConditionFalse}
	url, err := r.applyTSAIngress(ctx, cr)
	if blocked, ok := errors.AsType[*blockedError](err); ok {
		c.Reason, c.Message = blocked.reason, blocked.msg
		setCondition(cr, c)
		return nil
	}
	if err != nil {
		c.Reason, c.Message = "ApplyFailed", err.Error()
		setCondition(cr, c)
		return err
	}
	c.Status, c.Reason, c.Message = metav1.ConditionTrue, "Applied", "Ingress serves "+url
	setCondition(cr, c)
	if tsaAvailable {
		cr.Status.TSA.ExternalURL = url
	}
	return nil
}

func (r *SecureSignPQCReconciler) applyTSAIngress(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) (string, error) {
	openshift, err := r.servesRoutes()
	if err != nil {
		return "", err
	}
	host, err := r.tsaIngressHost(ctx, cr, openshift)
	if err != nil {
		return "", err
	}
	if err := r.Apply(ctx, tsaIngress(cr, host, openshift), client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		return "", err
	}
	scheme := "http"
	if openshift {
		scheme = "https"
	}
	return scheme + "://" + host, nil
}
