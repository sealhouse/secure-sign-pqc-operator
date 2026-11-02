package operator

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
)

func getIngress(ctx context.Context, ns string) (*networkingv1.Ingress, error) {
	var ing networkingv1.Ingress
	err := k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: controller.TSAName("demo")}, &ing)
	return &ing, err
}

func TestIngressRules(t *testing.T) {
	ctx := context.Background()
	ns := createNamespace(t, "ingress-crd")
	cr := newInstance(ns)
	cr.Spec.TSA.Ingress = pqcv1alpha1.IngressSpec{Enabled: true, Host: "tsa.example.com", Labels: map[string]string{"shard": "a"}}
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*pqcv1alpha1.SecureSignPQCSpec){
		"disable":       func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Ingress.Enabled = false },
		"remove":        func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Ingress = pqcv1alpha1.IngressSpec{} },
		"change labels": func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Ingress.Labels = map[string]string{"shard": "b"} },
		"drop labels":   func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Ingress.Labels = nil },
	} {
		bad := getCR(t, ns)
		edit(&bad.Spec)
		if err := k8s.Update(ctx, bad); !apierrors.IsInvalid(err) {
			t.Errorf("%s: got %v, want Invalid", name, err)
		}
	}
	// Without labels only the enabled rule can refuse removing the block.
	plain := newInstance(ns)
	plain.Name = "plain"
	plain.Spec.TSA.Ingress = pqcv1alpha1.IngressSpec{Enabled: true, Host: "plain.example.com"}
	if err := k8s.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	plain.Spec.TSA.Ingress = pqcv1alpha1.IngressSpec{}
	if err := k8s.Update(ctx, plain); !apierrors.IsInvalid(err) {
		t.Errorf("remove without labels: got %v, want Invalid", err)
	}
	for _, host := range []string{"TSA.example.com", "*.example.com", "tsa_1.example.com", "tsa.example.com.", strings.Repeat("a", 64) + ".example.com"} {
		bad := getCR(t, ns)
		bad.Spec.TSA.Ingress.Host = host
		if err := k8s.Update(ctx, bad); !apierrors.IsInvalid(err) {
			t.Errorf("host %q: got %v, want Invalid", host, err)
		}
	}
	ok := getCR(t, ns)
	ok.Spec.TSA.Ingress.Host = "tsa2.example.com"
	if err := k8s.Update(ctx, ok); err != nil {
		t.Errorf("change host: %v", err)
	}
}

// Off OpenShift the Ingress needs a host, and serves plain HTTP. Without
// one the TSA still runs and rotates.
func TestIngressKubernetes(t *testing.T) {
	ctx := context.Background()
	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "ingress")
	cr := newInstance(ns)
	cr.Spec.TSA.Ingress = pqcv1alpha1.IngressSpec{Enabled: true, Labels: map[string]string{"shard": "a"}}
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "IngressHostRequired", func() error {
		cr := getCR(t, ns)
		if err := conditionIs(cr, pqcv1alpha1.ConditionTSAIngressReady, metav1.ConditionFalse, "IngressHostRequired"); err != nil {
			return err
		}
		return conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Signing.SignerGeneration = 2 })
	eventually(t, 30*time.Second, "signer 2 pending", func() error {
		if got := signerStatus(getCR(t, ns)); got != "2:ML-DSA-65:Pending,1:ML-DSA-65:Active" {
			return fmt.Errorf("signers %s", got)
		}
		return nil
	})
	markAvailable(t, ns)
	eventually(t, 30*time.Second, "signer 1 retired", func() error {
		if got, want := keySecrets(t, ns), []string{"demo-tsa-ca", "demo-tsa-signer-2"}; !slices.Equal(got, want) {
			return fmt.Errorf("key Secrets %v", got)
		}
		return nil
	})

	setSpec(t, ns, func(s *pqcv1alpha1.SecureSignPQCSpec) { s.TSA.Ingress.Host = "tsa.example.com" })
	eventually(t, 30*time.Second, "external URL", func() error {
		cr := getCR(t, ns)
		if cr.Status.TSA.ExternalURL != "http://tsa.example.com" {
			return fmt.Errorf("externalURL %q", cr.Status.TSA.ExternalURL)
		}
		return conditionIs(cr, pqcv1alpha1.ConditionTSAIngressReady, metav1.ConditionTrue, "Applied")
	})
	ing, err := getIngress(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(ing.Spec.TLS) != 0 || ing.Annotations["route.openshift.io/termination"] != "" {
		t.Errorf("TLS %v, annotations %v off OpenShift", ing.Spec.TLS, ing.Annotations)
	}
	if ing.Labels["shard"] != "a" || ing.Labels[controller.LabelManagedBy] != controller.ManagedBy {
		t.Errorf("labels %v", ing.Labels)
	}
	rule := ing.Spec.Rules[0]
	if rule.Host != "tsa.example.com" || rule.HTTP.Paths[0].Backend.Service.Name != controller.TSAName("demo") {
		t.Errorf("rule %+v", rule)
	}

	// The operator puts back an Ingress someone deletes.
	if err := k8s.Delete(ctx, ing); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "Ingress recreated", func() error {
		got, err := getIngress(ctx, ns)
		if err != nil {
			return err
		}
		if got.UID == ing.UID {
			return fmt.Errorf("not yet deleted")
		}
		return nil
	})
}

// openShiftCRDs stand in for the Route and cluster Ingress config APIs.
func openShiftCRDs() []*apiextensionsv1.CustomResourceDefinition {
	return []*apiextensionsv1.CustomResourceDefinition{
		stubCRD("route.openshift.io", "routes", "Route", apiextensionsv1.NamespaceScoped),
		stubCRD("config.openshift.io", "ingresses", "Ingress", apiextensionsv1.ClusterScoped),
	}
}

// On OpenShift the host defaults from the cluster domain and the router
// terminates TLS.
func TestIngressOpenShift(t *testing.T) {
	ctx := context.Background()
	installCRDs(t, t, openShiftCRDs()...)
	cluster := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "config.openshift.io/v1", "kind": "Ingress",
		"metadata": map[string]any{"name": "cluster"},
		"spec":     map[string]any{"domain": "apps.example.com"},
	}}
	if err := k8s.Create(ctx, cluster); err != nil {
		t.Fatal(err)
	}

	startOperator(t, createNamespace(t, "op"), nil)
	ns := createNamespace(t, "ingress-ocp")
	cr := newInstance(ns)
	cr.Spec.TSA.Ingress = pqcv1alpha1.IngressSpec{Enabled: true}
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	markAvailable(t, ns)
	host := "demo-tsa-" + ns + ".apps.example.com"
	eventually(t, 30*time.Second, "external URL", func() error {
		cr := getCR(t, ns)
		if cr.Status.TSA.ExternalURL != "https://"+host {
			return fmt.Errorf("externalURL %q", cr.Status.TSA.ExternalURL)
		}
		return conditionIs(cr, pqcv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	ing, err := getIngress(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if ing.Spec.Rules[0].Host != host || len(ing.Spec.TLS) != 1 || ing.Annotations["route.openshift.io/termination"] != "edge" {
		t.Errorf("host %s, TLS %v, annotations %v", ing.Spec.Rules[0].Host, ing.Spec.TLS, ing.Annotations)
	}

	// A default host whose first label passes 63 characters needs spec.tsa.ingress.host.
	long := createNamespace(t, strings.Repeat("n", 50))
	cr = newInstance(long)
	cr.Spec.TSA.Ingress = pqcv1alpha1.IngressSpec{Enabled: true}
	if err := k8s.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "IngressHostTooLong", func() error {
		return conditionIs(getCR(t, long), pqcv1alpha1.ConditionTSAIngressReady, metav1.ConditionFalse, "IngressHostTooLong")
	})
}
