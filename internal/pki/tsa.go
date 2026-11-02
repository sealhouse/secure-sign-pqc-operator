// Package pki creates the ML-DSA keys and certificates the operator manages.
package pki

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// Secret data keys for a TSA signer (one per key generation) and for the
// TSA CA that issues the signers.
const (
	// KeyPEM is the leaf private key as an unencrypted PKCS #8 PEM block.
	KeyPEM = "key.pem"
	// ChainPEM is leaf, intermediate and root certificates, in that order.
	ChainPEM = "chain.pem"
	// RootPEM is the root certificate alone, the trust anchor for clients.
	RootPEM = "root.pem"
	// IntermediateKeyPEM is the intermediate CA's private key.
	IntermediateKeyPEM = "intermediate-key.pem"
	// IntermediatePEM is the intermediate CA certificate.
	IntermediatePEM = "intermediate.pem"
)

// Validity of each certificate in a TSA chain.
const (
	rootValidity         = 20 * 365 * 24 * time.Hour
	intermediateValidity = 15 * 365 * 24 * time.Hour
	leafValidity         = 10 * 365 * 24 * time.Hour
)

var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// Parameters returns the ML-DSA parameter set for a.
func Parameters(a pqcv1alpha1.Algorithm) (mldsa.Parameters, error) {
	switch a {
	case pqcv1alpha1.MLDSA44:
		return mldsa.MLDSA44(), nil
	case pqcv1alpha1.MLDSA65:
		return mldsa.MLDSA65(), nil
	case pqcv1alpha1.MLDSA87:
		return mldsa.MLDSA87(), nil
	}
	return mldsa.Parameters{}, fmt.Errorf("unsupported algorithm %q", a)
}

// Strength orders the ML-DSA parameter sets: a higher value is a stronger
// set.
func Strength(a pqcv1alpha1.Algorithm) int {
	switch a {
	case pqcv1alpha1.MLDSA44:
		return 1
	case pqcv1alpha1.MLDSA65:
		return 2
	case pqcv1alpha1.MLDSA87:
		return 3
	}
	return 0
}

// AlgorithmOf returns the Algorithm of an ML-DSA public key.
func AlgorithmOf(pub crypto.PublicKey) (pqcv1alpha1.Algorithm, error) {
	k, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("key is %T, not ML-DSA", pub)
	}
	for _, a := range []pqcv1alpha1.Algorithm{pqcv1alpha1.MLDSA44, pqcv1alpha1.MLDSA65, pqcv1alpha1.MLDSA87} {
		p, _ := Parameters(a)
		if k.Parameters() == p {
			return a, nil
		}
	}
	return "", errors.New("unknown ML-DSA parameter set")
}

// TSACA is the intermediate CA that issues an instance's timestamping
// certificates, with the root above it.
type TSACA struct {
	Key          *mldsa.PrivateKey
	Intermediate *x509.Certificate
	Root         *x509.Certificate
}

// TSAChain is a timestamping key with its certificate chain.
type TSAChain struct {
	Key          *mldsa.PrivateKey
	Leaf         *x509.Certificate
	Intermediate *x509.Certificate
	Root         *x509.Certificate
}

// Certificates returns leaf, intermediate, root.
func (c *TSAChain) Certificates() []*x509.Certificate {
	return []*x509.Certificate{c.Leaf, c.Intermediate, c.Root}
}

// NewTSACA creates a root CA and an intermediate CA, both with algorithm a.
func NewTSACA(a pqcv1alpha1.Algorithm, subject string, now time.Time) (*TSACA, error) {
	params, err := Parameters(a)
	if err != nil {
		return nil, err
	}
	rootKey, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	intKey, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	notBefore := now.Add(-5 * time.Minute)

	rootTmpl := &x509.Certificate{
		Subject:               name(subject + " TSA root"),
		NotBefore:             notBefore,
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	root, err := sign(rootTmpl, rootTmpl, rootKey.PublicKey(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}

	intTmpl := &x509.Certificate{
		Subject:               name(subject + " TSA intermediate"),
		NotBefore:             notBefore,
		NotAfter:              now.Add(intermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	intermediate, err := sign(intTmpl, root, intKey.PublicKey(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("intermediate: %w", err)
	}
	return &TSACA{Key: intKey, Intermediate: intermediate, Root: root}, nil
}

// IssueLeaf creates a timestamping key with algorithm a and a certificate
// for it signed by ca.
func (ca *TSACA) IssueLeaf(a pqcv1alpha1.Algorithm, subject string, now time.Time) (*TSAChain, error) {
	params, err := Parameters(a)
	if err != nil {
		return nil, err
	}
	leafKey, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, err
	}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafValidity)
	if notAfter.After(ca.Intermediate.NotAfter) {
		notAfter = ca.Intermediate.NotAfter
	}
	leafTmpl := &x509.Certificate{
		Subject:               name(subject + " TSA"),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidExtKeyUsage, Critical: true, Value: eku}},
	}
	leaf, err := sign(leafTmpl, ca.Intermediate, leafKey.PublicKey(), ca.Key)
	if err != nil {
		return nil, fmt.Errorf("leaf: %w", err)
	}
	return &TSAChain{Key: leafKey, Leaf: leaf, Intermediate: ca.Intermediate, Root: ca.Root}, nil
}

// NewTSAChain creates a CA and a first leaf, all with algorithm a.
func NewTSAChain(a pqcv1alpha1.Algorithm, subject string, now time.Time) (*TSAChain, error) {
	ca, err := NewTSACA(a, subject, now)
	if err != nil {
		return nil, err
	}
	return ca.IssueLeaf(a, subject, now)
}

// Encode returns the CA Secret data for ca.
func (ca *TSACA) Encode() (map[string][]byte, error) {
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

// Encode returns the signer Secret data for c.
func (c *TSAChain) Encode() (map[string][]byte, error) {
	key, err := encodeKey(c.Key)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		KeyPEM:   key,
		ChainPEM: encodeCerts(c.Certificates()...),
		RootPEM:  encodeCerts(c.Root),
	}, nil
}

// DecodeTSACA parses CA Secret data written by TSACA.Encode and checks that
// it is internally consistent: every key is ML-DSA, the key matches the
// intermediate, and the root signed the intermediate and itself.
func DecodeTSACA(data map[string][]byte) (*TSACA, error) {
	key, err := decodeKey(data, IntermediateKeyPEM)
	if err != nil {
		return nil, err
	}
	intermediate, err := singleCertificate(data, IntermediatePEM)
	if err != nil {
		return nil, err
	}
	root, err := singleCertificate(data, RootPEM)
	if err != nil {
		return nil, err
	}
	ca := &TSACA{Key: key, Intermediate: intermediate, Root: root}
	if !key.PublicKey().Equal(intermediate.PublicKey) {
		return nil, errors.New("private key does not match the intermediate certificate")
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
	return ca, nil
}

// DecodeTSAChain parses signer Secret data written by TSAChain.Encode and
// checks it against ca: the key matches the leaf, every key is ML-DSA (at
// any parameter set), the chain's intermediate and root are ca's, ca signed
// the leaf, and root.pem is the chain's root.
func DecodeTSAChain(data map[string][]byte, ca *TSACA) (*TSAChain, error) {
	key, err := decodeKey(data, KeyPEM)
	if err != nil {
		return nil, err
	}
	certs, err := parseCertificates(data[ChainPEM])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ChainPEM, err)
	}
	if len(certs) != 3 {
		return nil, fmt.Errorf("%s: want 3 certificates, got %d", ChainPEM, len(certs))
	}
	root, err := singleCertificate(data, RootPEM)
	if err != nil {
		return nil, err
	}
	if !root.Equal(certs[2]) {
		return nil, fmt.Errorf("%s does not match the root in %s", RootPEM, ChainPEM)
	}
	c := &TSAChain{Key: key, Leaf: certs[0], Intermediate: certs[1], Root: certs[2]}
	if !key.PublicKey().Equal(c.Leaf.PublicKey) {
		return nil, errors.New("private key does not match the leaf certificate")
	}
	if err := checkMLDSA(certs...); err != nil {
		return nil, err
	}
	if !c.Intermediate.Equal(ca.Intermediate) || !c.Root.Equal(ca.Root) {
		return nil, errors.New("chain is not issued by the instance's TSA CA")
	}
	if err := c.Leaf.CheckSignatureFrom(c.Intermediate); err != nil {
		return nil, fmt.Errorf("leaf not signed by intermediate: %w", err)
	}
	return c, nil
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
