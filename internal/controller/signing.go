package controller

import (
	"fmt"

	pqcv1alpha1 "github.com/sealhouse/secure-sign-pqc-operator/api/v1alpha1"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/pki"
)

// tsaSigning is the field path of the TSA's SigningSpec, for messages.
const tsaSigning = "spec.tsa.signing"

// signerGeneration is s's signer generation, at least 1.
func signerGeneration(s pqcv1alpha1.SigningSpec) int32 {
	return max(s.SignerGeneration, 1)
}

// checkWeaker refuses a new key at s's algorithm that is weaker than inUse,
// the newest key in use, unless s.acceptWeakerAlgorithm names that
// algorithm and s's generation. path is s's field path.
func checkWeaker(s pqcv1alpha1.SigningSpec, path string, inUse pqcv1alpha1.Algorithm) error {
	gen := signerGeneration(s)
	if a := s.AcceptWeakerAlgorithm; a != nil && a.Algorithm == s.Algorithm && a.SignerGeneration == gen {
		return nil
	}
	if pki.Strength(s.Algorithm) >= pki.Strength(inUse) {
		return nil
	}
	return &blockedError{
		reason: "WeakerAlgorithmNotAccepted",
		msg: fmt.Sprintf("signer generation %d would use %s, weaker than %s in use; set %s.acceptWeakerAlgorithm to {algorithm: %s, signerGeneration: %d} to accept it",
			gen, s.Algorithm, inUse, path, s.Algorithm, gen),
	}
}
