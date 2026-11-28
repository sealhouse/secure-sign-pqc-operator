package controller

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// logPart lists one transparency log, as a component with log keys would.
type logPart struct{ url string }

func (p logPart) component() string { return "log" }

func (p logPart) addTo(_ *pqcv1alpha1.SecureSignPQC, tr *prototrustroot.TrustedRoot) {
	tr.Tlogs = append(tr.Tlogs, &prototrustroot.TransparencyLogInstance{BaseUrl: p.url})
}

func loaderFor(p rootPart, calls *[]string) rootLoader {
	return rootLoader{p.component(), func(context.Context, *SecureSignPQCReconciler, *pqcv1alpha1.SecureSignPQC) (rootPart, error) {
		*calls = append(*calls, p.component())
		return p, nil
	}}
}

// A publish takes the caller's part in place of its component's stored
// one, loads every other component's, and keeps the loaders' order.
func TestRootParts(t *testing.T) {
	now := time.Now()
	stored := componentRecords{tsaCA, []chainRecord{{gen: caGen{1, 1}, chain: testCA(t, caGen{1, 1}, now, now, true).target.ca}}}
	fresh := componentRecords{tsaCA, []chainRecord{{gen: caGen{2, 1}, chain: testCA(t, caGen{2, 1}, now, now, true).target.ca}}}
	var calls []string
	loaders := []rootLoader{loaderFor(stored, &calls), loaderFor(logPart{"https://log.example"}, &calls)}
	r := &SecureSignPQCReconciler{}
	cr := testInstance()

	parts, err := r.rootParts(context.Background(), cr, loaders, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{"log"}) {
		t.Errorf("loaded %v, want only the log: the TSA's part is the caller's", calls)
	}
	raw, err := trustedRoot(cr, parts)
	if err != nil {
		t.Fatal(err)
	}
	var tr prototrustroot.TrustedRoot
	if err := protojson.Unmarshal(raw, &tr); err != nil {
		t.Fatal(err)
	}
	if !listsIntermediate(tsaCA, fresh.records[0].chain)(&tr) {
		t.Error("trusted root does not list the caller's intermediate")
	}
	if listsIntermediate(tsaCA, stored.records[0].chain)(&tr) {
		t.Error("trusted root lists the stored intermediate the caller's part replaced")
	}
	if logs := tr.GetTlogs(); len(logs) != 1 || logs[0].GetBaseUrl() != "https://log.example" {
		t.Errorf("tlogs %v, want the other component's log", logs)
	}

	calls = nil
	if parts, err = r.rootParts(context.Background(), cr, loaders, logPart{"https://new.example"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{tsaCA.name}) || len(parts) != 2 || parts[0].component() != tsaCA.name {
		t.Errorf("publishing the log: loaded %v, parts %v", calls, parts)
	}

	if _, err := r.rootParts(context.Background(), cr, loaders[1:], fresh); err == nil {
		t.Error("a part with no loader was published")
	}

	failing := rootLoader{"log", func(context.Context, *SecureSignPQCReconciler, *pqcv1alpha1.SecureSignPQC) (rootPart, error) {
		return nil, errors.New("list refused")
	}}
	if _, err := r.rootParts(context.Background(), cr, []rootLoader{loaders[0], failing}, fresh); err == nil {
		t.Error("a part that failed to load was left out instead of failing the publish")
	}
}
