package pki

import (
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// Secret data keys for a TSA signer, one per key generation.
const (
	// KeyPEM is the leaf private key as an unencrypted PKCS #8 PEM block.
	KeyPEM = "key.pem"
	// ChainPEM is leaf, intermediate and root certificates, in that order.
	ChainPEM = "chain.pem"
)

// TSAIntermediateEKU restricts a TSA intermediate to timestamping.
var TSAIntermediateEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

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

// IssueLeaf creates a timestamping key with algorithm a and a certificate
// for it signed by ca. It never outlives the intermediate.
func (ca *CA) IssueLeaf(a pqcv1alpha1.Algorithm, subject string, now time.Time) (*TSAChain, error) {
	leafKey, err := generateKey(a)
	if err != nil {
		return nil, err
	}
	// The leaf's timestamping EKU must be critical (RFC 3161), which
	// x509.Certificate.ExtKeyUsage cannot mark, so it is added raw.
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{oidKPTimeStamping})
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		Subject:               name(subject + " TSA"),
		NotBefore:             notBefore(now),
		NotAfter:              earliest(now.Add(LeafValidity), ca.Intermediate.NotAfter),
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

// DecodeTSAChain parses signer Secret data written by TSAChain.Encode and
// checks it against ca: the key matches the leaf, every key is ML-DSA (at
// any parameter set), the chain's intermediate and root are ca's, ca signed
// the leaf, and root.pem is the chain's root.
func DecodeTSAChain(data map[string][]byte, ca *CA) (*TSAChain, error) {
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
