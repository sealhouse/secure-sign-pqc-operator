package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
)

const (
	// TrustedRootKey is the trusted root ConfigMap's data key.
	TrustedRootKey       = "trusted_root.json"
	trustedRootMediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
	// AnnotationRetiredAt on a chain record is when its CA stopped being
	// used, the end of its trusted root entry.
	AnnotationRetiredAt = "pqc.rhtas.redhat.com/retired-at"
)

// TrustedRootName is the ConfigMap holding an instance's Sigstore trusted
// root.
func TrustedRootName(instance string) string { return instance + "-trusted-root" }

// chainRecord is the public chain of one intermediate. It outlives the
// intermediate's key Secret, so the trusted root keeps retired CAs.
type chainRecord struct {
	gen       caGen
	name      string
	chain     *pki.CA
	retiredAt *time.Time
}

// ensureChainRecords creates a chain record for each of st's intermediates
// and returns every record of c, newest first.
func (r *SecureSignPQCReconciler) ensureChainRecords(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent, st *caState) ([]chainRecord, error) {
	for _, k := range st.cas {
		key := types.NamespacedName{Namespace: cr.Namespace, Name: c.chainName(cr.Name, k.gen)}
		cm := &corev1.ConfigMap{}
		if _, err := r.createIfAbsent(ctx, key, cm, func() error {
			data := map[string]string{}
			for f, v := range k.ca.EncodeChain() {
				data[f] = string(v)
			}
			*cm = corev1.ConfigMap{
				Namespace: key.Namespace, Name: key.Name,
				Labels: c.genLabels(cr, c.roleChain, k.gen),
				Data:   data,
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return r.listChainRecords(ctx, cr, c, st)
}

// listChainRecords returns every chain record of c, newest first. With st,
// a record must match the CA Secret of its generation, if there is one.
func (r *SecureSignPQCReconciler) listChainRecords(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent, st *caState) ([]chainRecord, error) {
	var list corev1.ConfigMapList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(cr.Namespace),
		client.MatchingLabels{LabelInstance: cr.Name, LabelKeyRole: c.roleChain}); err != nil {
		return nil, err
	}
	records := make([]chainRecord, 0, len(list.Items))
	for i := range list.Items {
		cm := &list.Items[i]
		g, err := labelCAGen(cm)
		if err != nil {
			return nil, invalidConfigMap(cm.Name, err)
		}
		data := map[string][]byte{}
		for f, v := range cm.Data {
			data[f] = []byte(v)
		}
		chain, err := pki.DecodeChain(data)
		if err != nil {
			return nil, invalidConfigMap(cm.Name, err)
		}
		rec := chainRecord{gen: g, name: cm.Name, chain: chain}
		if v, ok := cm.Annotations[AnnotationRetiredAt]; ok {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, invalidConfigMap(cm.Name, fmt.Errorf("annotation %s: %w", AnnotationRetiredAt, err))
			}
			rec.retiredAt = &t
		}
		if st != nil {
			if k := st.find(g); k != nil && !k.ca.Intermediate.Equal(chain.Intermediate) {
				return nil, invalidConfigMap(cm.Name, fmt.Errorf("does not match CA Secret %s", k.secret.Name))
			}
		}
		records = append(records, rec)
	}
	slices.SortFunc(records, func(a, b chainRecord) int { return b.gen.compare(a.gen) })
	return records, nil
}

// retirementGrace is how long after a rollout an old pod can still sign:
// a terminating pod serves until it exits, within the default termination
// grace period the TSA pods use.
const retirementGrace = corev1.DefaultTerminationGracePeriodSeconds * time.Second

// markChainRetired records when the intermediate g stopped being used: the
// end of the grace period after now, rounded up to the second, so no
// timestamp an old pod issued falls after its trusted root entry ends.
func (r *SecureSignPQCReconciler) markChainRetired(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent, g caGen, now time.Time) error {
	var cm corev1.ConfigMap
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: c.chainName(cr.Name, g)}, &cm); err != nil {
		return err
	}
	if _, ok := cm.Annotations[AnnotationRetiredAt]; ok {
		return nil
	}
	patch := client.MergeFromWithOptions(cm.DeepCopy(), client.MergeFromWithOptimisticLock{})
	end := now.Add(retirementGrace).Truncate(time.Second).Add(time.Second)
	metav1.SetMetaDataAnnotation(&cm.ObjectMeta, AnnotationRetiredAt, end.UTC().Format(time.RFC3339))
	return r.Patch(ctx, &cm, patch)
}

// rootPart is one component's entries in the trusted root.
type rootPart interface {
	// component is the name of the component, as rootLoaders lists it.
	component() string
	addTo(cr *pqcv1alpha1.SecureSignPQC, tr *prototrustroot.TrustedRoot)
}

// componentRecords are one CA component's chain records, newest first.
type componentRecords struct {
	c       caComponent
	records []chainRecord
}

func (cc componentRecords) component() string { return cc.c.name }

// addTo lists one entry per intermediate, without a leaf, so a signer
// rotation leaves the trusted root unchanged. Signatures and timestamps
// carry their signing certificate.
func (cc componentRecords) addTo(cr *pqcv1alpha1.SecureSignPQC, tr *prototrustroot.TrustedRoot) {
	list := cc.c.authorities(tr)
	// Oldest first, as Sigstore's own trusted roots list them.
	for _, rec := range slices.Backward(cc.records) {
		validFor := &protocommon.TimeRange{Start: timestamppb.New(rec.chain.Intermediate.NotBefore)}
		if rec.retiredAt != nil {
			validFor.End = timestamppb.New(*rec.retiredAt)
		}
		*list = append(*list, &prototrustroot.CertificateAuthority{
			Subject: &protocommon.DistinguishedName{
				Organization: rec.chain.Intermediate.Subject.Organization[0],
				CommonName:   rec.chain.Intermediate.Subject.CommonName,
			},
			Uri: cc.c.url(cr),
			CertChain: &protocommon.X509CertificateChain{Certificates: []*protocommon.X509Certificate{
				{RawBytes: rec.chain.Intermediate.Raw},
				{RawBytes: rec.chain.Root.Raw},
			}},
			ValidFor: validFor,
		})
	}
}

// rootLoader reads one component's entries from the API server.
type rootLoader struct {
	component string
	load      func(context.Context, *SecureSignPQCReconciler, *pqcv1alpha1.SecureSignPQC) (rootPart, error)
}

// rootLoaders are the components with entries in the trusted root, in the
// order it lists them. A component's records outlive its Deployment, so
// each is loaded whether or not the component is enabled.
var rootLoaders = []rootLoader{
	{tsaCA.name, func(ctx context.Context, r *SecureSignPQCReconciler, cr *pqcv1alpha1.SecureSignPQC) (rootPart, error) {
		records, err := r.listChainRecords(ctx, cr, tsaCA, nil)
		return componentRecords{tsaCA, records}, err
	}},
}

// rootParts is every loader's part, with own in place of its component's:
// the caller's part is fresher than what the API server holds.
func (r *SecureSignPQCReconciler) rootParts(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, loaders []rootLoader, own rootPart) ([]rootPart, error) {
	parts := make([]rootPart, 0, len(loaders))
	found := false
	for _, l := range loaders {
		if l.component == own.component() {
			parts, found = append(parts, own), true
			continue
		}
		p, err := l.load(ctx, r, cr)
		if err != nil {
			return nil, err
		}
		parts = append(parts, p)
	}
	if !found {
		return nil, fmt.Errorf("component %s has no trusted root loader", own.component())
	}
	return parts, nil
}

// trustedRoot is the Sigstore trusted root of parts.
func trustedRoot(cr *pqcv1alpha1.SecureSignPQC, parts []rootPart) ([]byte, error) {
	tr := &prototrustroot.TrustedRoot{MediaType: trustedRootMediaType}
	for _, p := range parts {
		p.addTo(cr, tr)
	}
	return protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(tr)
}

// publishTrustedRoot applies the trusted root, with own and every other
// component's entries, and returns once listed accepts it as read back from
// the API server: a component must not sign with a key clients cannot
// verify yet. what names the entry listed looks for.
func (r *SecureSignPQCReconciler) publishTrustedRoot(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, own rootPart, listed func(*prototrustroot.TrustedRoot) bool, what string) error {
	parts, err := r.rootParts(ctx, cr, rootLoaders, own)
	if err != nil {
		return err
	}
	raw, err := trustedRoot(cr, parts)
	if err != nil {
		return err
	}
	name := TrustedRootName(cr.Name)
	cm := corev1ac.ConfigMap(name, cr.Namespace).
		WithLabels(map[string]string{LabelName: "trusted-root", LabelInstance: cr.Name, LabelManagedBy: ManagedBy}).
		WithOwnerReferences(ownerReference(cr)).
		WithData(map[string]string{TrustedRootKey: string(raw)})
	if err := r.Apply(ctx, cm, client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		return err
	}
	var live corev1.ConfigMap
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: name}, &live); err != nil {
		return err
	}
	var published prototrustroot.TrustedRoot
	if err := protojson.Unmarshal([]byte(live.Data[TrustedRootKey]), &published); err != nil {
		return fmt.Errorf("ConfigMap %s: %w", name, err)
	}
	if !listed(&published) {
		return fmt.Errorf("trusted root %s does not list %s yet", name, what)
	}
	return nil
}

// listsIntermediate reports whether c's entries in tr include target's
// intermediate.
func listsIntermediate(c caComponent, target *pki.CA) func(*prototrustroot.TrustedRoot) bool {
	return func(tr *prototrustroot.TrustedRoot) bool {
		for _, ca := range *c.authorities(tr) {
			if certs := ca.GetCertChain().GetCertificates(); len(certs) > 0 && bytes.Equal(certs[0].GetRawBytes(), target.Intermediate.Raw) {
				return true
			}
		}
		return false
	}
}

// publishCARoot publishes the trusted root with c's records and waits for
// it to list target's intermediate.
func (r *SecureSignPQCReconciler) publishCARoot(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, c caComponent, records []chainRecord, target *pki.CA) error {
	return r.publishTrustedRoot(ctx, cr, componentRecords{c, records}, listsIntermediate(c, target),
		fmt.Sprintf("%s intermediate %s", c.title, target.Intermediate.SerialNumber.Text(16)))
}

// caStatus lists c's roots and intermediates from its chain records, newest
// first, each root before its intermediates. targetPending marks the
// target intermediate as not yet used by every pod.
func caStatus(records []chainRecord, target caGen, targetPending bool) []pqcv1alpha1.CAStatus {
	var out []pqcv1alpha1.CAStatus
	for i := 0; i < len(records); {
		j := i
		for j < len(records) && records[j].gen.root == records[i].gen.root {
			j++
		}
		group := records[i:j]
		root := group[0].chain.Root
		var inter []pqcv1alpha1.CAStatus
		retired, pending := 0, 0
		var lastRetired *time.Time
		for _, rec := range group {
			s := caEntry(rec.chain.Intermediate, root, pqcv1alpha1.CAIntermediate, rec.gen)
			s.IntermediateGeneration = rec.gen.intermediate
			switch {
			case rec.retiredAt != nil:
				s.Stage = pqcv1alpha1.KeyRetired
				s.RetiredAt = &metav1.Time{Time: *rec.retiredAt}
				retired++
				if lastRetired == nil || rec.retiredAt.After(*lastRetired) {
					lastRetired = rec.retiredAt
				}
			case rec.gen == target && targetPending:
				s.Stage = pqcv1alpha1.KeyPending
				pending++
			}
			inter = append(inter, s)
		}
		rs := caEntry(root, nil, pqcv1alpha1.CARoot, group[0].gen)
		switch {
		case retired == len(group):
			rs.Stage = pqcv1alpha1.KeyRetired
			rs.RetiredAt = &metav1.Time{Time: *lastRetired}
		case pending == len(group):
			rs.Stage = pqcv1alpha1.KeyPending
		}
		out = append(out, rs)
		out = append(out, inter...)
		i = j
	}
	return out
}

// caEntry is an Active entry for the CA certificate cert, issued by issuer,
// which is nil for a root.
func caEntry(cert, issuer *x509.Certificate, kind pqcv1alpha1.CAKind, g caGen) pqcv1alpha1.CAStatus {
	return pqcv1alpha1.CAStatus{
		Kind:              kind,
		RootGeneration:    g.root,
		CertificateStatus: certificateStatus(cert, issuer, pqcv1alpha1.KeyActive),
	}
}

func invalidConfigMap(name string, err error) error {
	return &invalidSignerError{object: "ConfigMap " + name, err: err}
}
