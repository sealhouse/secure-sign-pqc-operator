// Package v2_0 is the profile for product version 2.0: the ML-DSA timestamp
// authority.
package v2_0

import (
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
	imagesfs "github.com/sealhouse/secure-sign-pqc-operator/versions"
)

// Version is the spec.version value of this profile.
const Version = "2.0"

// Profile loads the 2.0 profile from the embedded images.env.
func Profile() (*versions.Profile, error) {
	images, err := versions.LoadImages(imagesfs.FS, Version)
	if err != nil {
		return nil, err
	}
	return &versions.Profile{
		Version:      Version,
		Images:       images,
		Capabilities: []versions.Capability{versions.CapabilityTSA},
	}, nil
}
