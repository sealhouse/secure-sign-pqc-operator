// Package pki creates the ML-DSA keys and certificates the operator manages.
package pki

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// Secret data keys for a root CA and for an intermediate CA.
const (
	// RootKeyPEM is the root CA's private key.
	RootKeyPEM = "root-key.pem"
	// RootPEM is the root certificate alone, the trust anchor for clients.
	RootPEM = "root.pem"
	// IntermediateKeyPEM is the intermediate CA's private key.
	IntermediateKeyPEM = "intermediate-key.pem"
	// IntermediatePEM is the intermediate CA certificate.
	IntermediatePEM = "intermediate.pem"
)

// Default lifetimes, as Sigstore's certificate-maker issues them.
const (
	RootValidity         = 10 * 365 * 24 * time.Hour
	IntermediateValidity = 5 * 365 * 24 * time.Hour
	LeafValidity         = 365 * 24 * time.Hour
)

// parameterSets are the ML-DSA parameter sets, weakest first.
var parameterSets = []struct {
	algorithm  pqcv1alpha1.Algorithm
	parameters mldsa.Parameters
}{
	{pqcv1alpha1.MLDSA44, mldsa.MLDSA44()},
	{pqcv1alpha1.MLDSA65, mldsa.MLDSA65()},
	{pqcv1alpha1.MLDSA87, mldsa.MLDSA87()},
}

// Algorithms returns the supported algorithms, weakest first.
func Algorithms() []pqcv1alpha1.Algorithm {
	out := make([]pqcv1alpha1.Algorithm, 0, len(parameterSets))
	for _, s := range parameterSets {
		out = append(out, s.algorithm)
	}
	return out
}

// Parameters returns the ML-DSA parameter set for a.
func Parameters(a pqcv1alpha1.Algorithm) (mldsa.Parameters, error) {
	for _, s := range parameterSets {
		if s.algorithm == a {
			return s.parameters, nil
		}
	}
	return mldsa.Parameters{}, fmt.Errorf("unsupported algorithm %q", a)
}

// Strength orders the ML-DSA parameter sets: a higher value is a stronger
// set, and 0 is no known set.
func Strength(a pqcv1alpha1.Algorithm) int {
	for i, s := range parameterSets {
		if s.algorithm == a {
			return i + 1
		}
	}
	return 0
}

// AlgorithmOf returns the Algorithm of an ML-DSA public key.
func AlgorithmOf(pub crypto.PublicKey) (pqcv1alpha1.Algorithm, error) {
	k, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("key is %T, not ML-DSA", pub)
	}
	for _, s := range parameterSets {
		if k.Parameters() == s.parameters {
			return s.algorithm, nil
		}
	}
	return "", errors.New("unknown ML-DSA parameter set")
}

// generateKey creates a key with algorithm a.
func generateKey(a pqcv1alpha1.Algorithm) (*mldsa.PrivateKey, error) {
	params, err := Parameters(a)
	if err != nil {
		return nil, err
	}
	return mldsa.GenerateKey(params)
}

// notBefore backdates a certificate's start, for clocks slightly behind
// the operator's.
func notBefore(now time.Time) time.Time { return now.Add(-5 * time.Minute) }

// Root is a root CA with its private key.
type Root struct {
	Key  *mldsa.PrivateKey
	Cert *x509.Certificate
}

// CA is an intermediate CA with the root above it.
type CA struct {
	Key          *mldsa.PrivateKey
	Intermediate *x509.Certificate
	Root         *x509.Certificate
}

// NewRoot creates a self-signed root CA with algorithm a.
func NewRoot(a pqcv1alpha1.Algorithm, commonName string, now time.Time) (*Root, error) {
	key, err := generateKey(a)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Subject:               name(commonName),
		NotBefore:             notBefore(now),
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	cert, err := sign(tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}
	return &Root{Key: key, Cert: cert}, nil
}

// IssueIntermediate creates an intermediate CA with algorithm a under r,
// restricted to eku. It never outlives r.
func (r *Root) IssueIntermediate(a pqcv1alpha1.Algorithm, commonName string, eku []x509.ExtKeyUsage, now time.Time) (*CA, error) {
	key, err := generateKey(a)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Subject:               name(commonName),
		NotBefore:             notBefore(now),
		NotAfter:              earliest(now.Add(IntermediateValidity), r.Cert.NotAfter),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	cert, err := sign(tmpl, r.Cert, key.PublicKey(), r.Key)
	if err != nil {
		return nil, fmt.Errorf("intermediate: %w", err)
	}
	return &CA{Key: key, Intermediate: cert, Root: r.Cert}, nil
}

// Encode returns the root Secret data for r.
func (r *Root) Encode() (map[string][]byte, error) {
	key, err := encodeKey(r.Key)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{RootKeyPEM: key, RootPEM: encodeCerts(r.Cert)}, nil
}

// Encode returns the intermediate Secret data for ca.
func (ca *CA) Encode() (map[string][]byte, error) {
	key, err := encodeKey(ca.Key)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		IntermediateKeyPEM: key,
		IntermediatePEM:    encodeCerts(ca.Intermediate),
		RootPEM:            encodeCerts(ca.Root),
	}, nil
}

// DecodeRoot parses root Secret data written by Root.Encode and checks that
// the key is ML-DSA, matches the certificate, and self-signed it.
func DecodeRoot(data map[string][]byte) (*Root, error) {
	key, err := decodeKey(data, RootKeyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := singleCertificate(data, RootPEM)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey().Equal(cert.PublicKey) {
		return nil, errors.New("private key does not match the root certificate")
	}
	if err := checkMLDSA(cert); err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("root must be a CA certificate")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("root not self-signed: %w", err)
	}
	return &Root{Key: key, Cert: cert}, nil
}

// DecodeCA parses intermediate Secret data written by CA.Encode and checks
// that it is internally consistent: every key is ML-DSA, the key matches the
// intermediate, and the root signed the intermediate and itself.
func DecodeCA(data map[string][]byte) (*CA, error) {
	key, err := decodeKey(data, IntermediateKeyPEM)
	if err != nil {
		return nil, err
	}
	chain, err := DecodeChain(data)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey().Equal(chain.Intermediate.PublicKey) {
		return nil, errors.New("private key does not match the intermediate certificate")
	}
	chain.Key = key
	return chain, nil
}

// DecodeChain parses the public intermediate and root of CA data, with the
// same checks as DecodeCA apart from the key, which it leaves nil.
func DecodeChain(data map[string][]byte) (*CA, error) {
	intermediate, err := singleCertificate(data, IntermediatePEM)
	if err != nil {
		return nil, err
	}
	root, err := singleCertificate(data, RootPEM)
	if err != nil {
		return nil, err
	}
	if err := checkMLDSA(intermediate, root); err != nil {
		return nil, err
	}
	if !intermediate.IsCA || !root.IsCA {
		return nil, errors.New("intermediate and root must both be CA certificates")
	}
	if err := intermediate.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("intermediate not signed by root: %w", err)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("root not self-signed: %w", err)
	}
	return &CA{Intermediate: intermediate, Root: root}, nil
}

// EncodeChain returns the public part of ca's Secret data.
func (ca *CA) EncodeChain() map[string][]byte {
	return map[string][]byte{
		IntermediatePEM: encodeCerts(ca.Intermediate),
		RootPEM:         encodeCerts(ca.Root),
	}
}

// checkMLDSA rejects any certificate whose key is not ML-DSA.
func checkMLDSA(certs ...*x509.Certificate) error {
	for _, cert := range certs {
		if _, err := AlgorithmOf(cert.PublicKey); err != nil {
			return fmt.Errorf("%s: %w", cert.Subject.CommonName, err)
		}
	}
	return nil
}

func encodeKey(k *mldsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeCerts(certs ...*x509.Certificate) []byte {
	blocks := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		blocks = append(blocks, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	return bytes.Join(blocks, nil)
}

func decodeKey(data map[string][]byte, field string) (*mldsa.PrivateKey, error) {
	block, _ := pem.Decode(data[field])
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: no PRIVATE KEY block", field)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	key, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: key is %T, not ML-DSA", field, parsed)
	}
	return key, nil
}

func singleCertificate(data map[string][]byte, field string) (*x509.Certificate, error) {
	certs, err := parseCertificates(data[field])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%s: want 1 certificate, got %d", field, len(certs))
	}
	return certs[0], nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected %s block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates")
	}
	return out, nil
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func name(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{"RHTAS PQC"}}
}

func sign(tmpl, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
