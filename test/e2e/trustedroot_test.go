//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/digitorus/timestamp"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/timestamp-authority/v2/pkg/verification"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/controller"
)

// stamped is a timestamp response for a fresh artifact.
type stamped struct {
	artifact []byte
	nonce    *big.Int
	tsr      []byte
}

// stamp asks cr's TSA, through its Service, for a timestamp of a fresh
// artifact.
func stamp(ctx context.Context, cr *pqcv1alpha1.SecureSignPQC) (*stamped, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s := &stamped{artifact: []byte("sealhouse e2e " + cr.Namespace + "/" + cr.Name + " " + now)}
	var err error
	if s.nonce, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63)); err != nil {
		return nil, err
	}
	req, err := timestamp.CreateRequest(bytes.NewReader(s.artifact), &timestamp.RequestOptions{
		Hash: crypto.SHA256, Certificates: true, Nonce: s.nonce,
	})
	if err != nil {
		return nil, err
	}
	s.tsr, err = requestTimestamp(ctx, cr.Namespace, controller.TSAName(cr.Name), req)
	return s, err
}

// verifyTrusted verifies s against cr's published trusted root, as a client
// would: against any TSA entry whose chain and validity period accept it.
// It returns the timestamp and the entry's intermediate.
func verifyTrusted(
	ctx context.Context, cr *pqcv1alpha1.SecureSignPQC, s *stamped,
) (*timestamp.Timestamp, *x509.Certificate, error) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: cr.Namespace, Name: controller.TrustedRootName(cr.Name)}
	if err := k8s.Get(ctx, key, &cm); err != nil {
		return nil, nil, err
	}
	var tr prototrustroot.TrustedRoot
	if err := protojson.Unmarshal([]byte(cm.Data[controller.TrustedRootKey]), &tr); err != nil {
		return nil, nil, err
	}
	var errs []error
	for _, ta := range tr.GetTimestampAuthorities() {
		subject := ta.GetSubject().GetCommonName()
		var certs []*x509.Certificate
		for _, c := range ta.GetCertChain().GetCertificates() {
			cert, err := x509.ParseCertificate(c.GetRawBytes())
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, cert)
		}
		if len(certs) != 2 {
			return nil, nil, fmt.Errorf("entry %s has %d certificates, want intermediate and root", subject, len(certs))
		}
		ts, err := verification.VerifyTimestampResponse(s.tsr, bytes.NewReader(s.artifact), verification.VerifyOpts{
			Roots: []*x509.Certificate{certs[1]}, Intermediates: []*x509.Certificate{certs[0]}, Nonce: s.nonce,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", subject, err))
			continue
		}
		v := ta.GetValidFor()
		if ts.Time.Before(v.GetStart().AsTime()) || (v.End != nil && ts.Time.After(v.GetEnd().AsTime())) {
			errs = append(errs, fmt.Errorf("%s: timestamp %s outside its validity period", subject, ts.Time))
			continue
		}
		return ts, certs[0], nil
	}
	return nil, nil, fmt.Errorf("no trusted root entry verifies the timestamp: %w", errors.Join(errs...))
}

// signingCert is the signing certificate a timestamp carries.
func signingCert(ts *timestamp.Timestamp) (*x509.Certificate, error) {
	for _, c := range ts.Certificates {
		if !c.IsCA {
			return c, nil
		}
	}
	return nil, errors.New("response carries no signing certificate")
}

// caStages describes status.tsa.cas, one CAStatus.String each.
func caStages(cr *pqcv1alpha1.SecureSignPQC) []string {
	out := make([]string, 0, len(cr.Status.TSA.CAs))
	for _, k := range cr.Status.TSA.CAs {
		out = append(out, k.String())
	}
	return out
}
