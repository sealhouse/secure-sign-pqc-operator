package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/timestamp-authority/v2/pkg/signer"
	tsx509 "github.com/sigstore/timestamp-authority/v2/pkg/x509"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

var algorithms = []pqcv1alpha1.Algorithm{pqcv1alpha1.MLDSA44, pqcv1alpha1.MLDSA65, pqcv1alpha1.MLDSA87}

// passesUpstreamChecks runs the timestamp-server's own startup checks on
// chain: the file signer loads key.pem exactly as the server does, and
// VerifyCertChain runs with intermediate EKU enforcement on, the server
// default.
func passesUpstreamChecks(t *testing.T, chain *TSAChain) {
	t.Helper()
	data, err := chain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), KeyPEM)
	if err := os.WriteFile(keyPath, data[KeyPEM], 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := signer.NewFileSigner(keyPath, "", crypto.SHA512)
	if err != nil {
		t.Fatalf("upstream file signer rejected key.pem: %v", err)
	}
	if err := tsx509.VerifyCertChain(chain.Certificates(), fs, true); err != nil {
		t.Fatalf("upstream VerifyCertChain: %v", err)
	}
}

func TestTSAChainPassesUpstreamChecks(t *testing.T) {
	for _, a := range algorithms {
		t.Run(string(a), func(t *testing.T) {
			chain, err := NewTSAChain(a, "test", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			passesUpstreamChecks(t, chain)
			got, err := AlgorithmOf(chain.Root.PublicKey)
			if err != nil || got != a {
				t.Fatalf("root algorithm %v, %v; want %s", got, err, a)
			}
		})
	}
}

// A rotated leaf may use a different ML-DSA parameter set from its CA.
func TestMixedLevelChainPassesUpstreamChecks(t *testing.T) {
	for _, caAlg := range algorithms {
		ca, err := NewTSACA(caAlg, "test", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, leafAlg := range algorithms {
			t.Run(fmt.Sprintf("%s CA %s leaf", caAlg, leafAlg), func(t *testing.T) {
				chain, err := ca.IssueLeaf(leafAlg, "test", time.Now())
				if err != nil {
					t.Fatal(err)
				}
				passesUpstreamChecks(t, chain)
				data, _ := chain.Encode()
				got, err := DecodeTSAChain(data, ca)
				if err != nil {
					t.Fatal(err)
				}
				if a, _ := AlgorithmOf(got.Leaf.PublicKey); a != leafAlg {
					t.Fatalf("leaf algorithm %s, want %s", a, leafAlg)
				}
			})
		}
	}
}

func TestLeafExpiresWithIntermediate(t *testing.T) {
	ca, err := NewTSACA(pqcv1alpha1.MLDSA65, "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Issued 14 years into a 15-year intermediate.
	later := time.Now().Add(14 * 365 * 24 * time.Hour)
	chain, err := ca.IssueLeaf(pqcv1alpha1.MLDSA65, "test", later)
	if err != nil {
		t.Fatal(err)
	}
	if !chain.Leaf.NotAfter.Equal(ca.Intermediate.NotAfter) {
		t.Fatalf("leaf NotAfter %s, intermediate NotAfter %s", chain.Leaf.NotAfter, ca.Intermediate.NotAfter)
	}
}

func TestDecodeTSACARoundTrip(t *testing.T) {
	ca, err := NewTSACA(pqcv1alpha1.MLDSA87, "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := ca.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := data[KeyPEM]; ok {
		t.Fatal("CA Secret data has a leaf key field")
	}
	got, err := DecodeTSACA(data)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Root.Equal(ca.Root) || !got.Intermediate.Equal(ca.Intermediate) || !got.Key.Equal(ca.Key) {
		t.Fatal("decoded CA differs from the encoded one")
	}
}

func TestDecodeTSAChainRoundTrip(t *testing.T) {
	ca, err := NewTSACA(pqcv1alpha1.MLDSA65, "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.IssueLeaf(pqcv1alpha1.MLDSA65, "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := chain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTSAChain(data, ca)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Root.Equal(chain.Root) || !got.Leaf.Equal(chain.Leaf) || !got.Key.Equal(chain.Key) {
		t.Fatal("decoded chain differs from the encoded one")
	}
}

// classicalChain is an ECDSA P-256 root, intermediate and leaf, built with
// the same templates as an ML-DSA chain.
func classicalChain(t *testing.T) (key *ecdsa.PrivateKey, certs []*x509.Certificate) {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rootKey, intKey, leafKey := gen(), gen(), gen()
	now := time.Now()
	rootTmpl := &x509.Certificate{Subject: name("classical root"), NotBefore: now, NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	root, err := sign(rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intTmpl := &x509.Certificate{Subject: name("classical intermediate"), NotBefore: now, NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	intermediate, err := sign(intTmpl, root, intKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := sign(&x509.Certificate{Subject: name("classical leaf"), NotBefore: now, NotAfter: now.Add(time.Hour)},
		intermediate, leafKey.Public(), intKey)
	if err != nil {
		t.Fatal(err)
	}
	return leafKey, []*x509.Certificate{leaf, intermediate, root}
}

func pemKey(t *testing.T, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestDecodeTSACARejects(t *testing.T) {
	a, err := NewTSACA(pqcv1alpha1.MLDSA65, "a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTSACA(pqcv1alpha1.MLDSA65, "b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	da, _ := a.Encode()
	db, _ := b.Encode()
	ecKey, ec := classicalChain(t)

	cases := map[string]struct {
		data map[string][]byte
		want string
	}{
		"classical key":       {map[string][]byte{IntermediateKeyPEM: pemKey(t, ecKey), IntermediatePEM: encodeCerts(ec[1]), RootPEM: encodeCerts(ec[2])}, "not ML-DSA"},
		"key from elsewhere":  {map[string][]byte{IntermediateKeyPEM: db[IntermediateKeyPEM], IntermediatePEM: da[IntermediatePEM], RootPEM: da[RootPEM]}, "does not match the intermediate"},
		"root from elsewhere": {map[string][]byte{IntermediateKeyPEM: da[IntermediateKeyPEM], IntermediatePEM: da[IntermediatePEM], RootPEM: db[RootPEM]}, "intermediate not signed by root"},
		"missing key":         {map[string][]byte{IntermediatePEM: da[IntermediatePEM], RootPEM: da[RootPEM]}, "no PRIVATE KEY"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeTSACA(tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestDecodeTSAChainRejects(t *testing.T) {
	caA, err := NewTSACA(pqcv1alpha1.MLDSA65, "a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	caB, err := NewTSACA(pqcv1alpha1.MLDSA65, "b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := caA.IssueLeaf(pqcv1alpha1.MLDSA65, "a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a2, err := caA.IssueLeaf(pqcv1alpha1.MLDSA65, "a2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := caB.IssueLeaf(pqcv1alpha1.MLDSA65, "b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	da, _ := a.Encode()
	db, _ := b.Encode()
	ecKey, ec := classicalChain(t)

	// A leaf under a's intermediate whose certificate was signed by b's.
	forged := *a2.Leaf
	forgedCert, err := sign(&forged, b.Intermediate, a2.Key.PublicKey(), caB.Key)
	if err != nil {
		t.Fatal(err)
	}
	forgedKey, _ := encodeKey(a2.Key)

	cases := map[string]struct {
		data map[string][]byte
		want string
	}{
		"classical chain":    {map[string][]byte{KeyPEM: pemKey(t, ecKey), ChainPEM: encodeCerts(ec...), RootPEM: encodeCerts(ec[2])}, "not ML-DSA"},
		"key from elsewhere": {map[string][]byte{KeyPEM: db[KeyPEM], ChainPEM: da[ChainPEM], RootPEM: da[RootPEM]}, "does not match the leaf"},
		"root mismatch":      {map[string][]byte{KeyPEM: da[KeyPEM], ChainPEM: da[ChainPEM], RootPEM: db[RootPEM]}, "does not match the root"},
		"missing key":        {map[string][]byte{ChainPEM: da[ChainPEM], RootPEM: da[RootPEM]}, "no PRIVATE KEY"},
		"other CA":           {db, "not issued by the instance's TSA CA"},
		"leaf signed by other CA": {map[string][]byte{
			KeyPEM:   forgedKey,
			ChainPEM: encodeCerts(forgedCert, caA.Intermediate, caA.Root),
			RootPEM:  encodeCerts(caA.Root),
		}, "leaf not signed by intermediate"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeTSAChain(tc.data, caA)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}
