// Package supported lists the product versions this operator build supports,
// oldest first.
package supported

import (
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/v2_0"
)

// Load returns every supported profile, oldest first.
func Load() (versions.Set, error) {
	p20, err := v2_0.Profile()
	if err != nil {
		return nil, err
	}
	return versions.Set{p20}, nil
}
