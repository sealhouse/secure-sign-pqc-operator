package controller

import (
	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
)

// tsaSigning is the field path of the TSA's SigningSpec, for messages.
const tsaSigning = "spec.tsa.signing"

// signerGeneration is s's signer generation, at least 1.
func signerGeneration(s pqcv1alpha1.SigningSpec) int32 {
	return max(s.SignerGeneration, 1)
}
