package v2_0

import (
	"testing"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
)

func TestProfileHasEveryImageItsCapabilitiesNeed(t *testing.T) {
	p, err := Profile()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Has(versions.CapabilityTSA) {
		t.Fatal("2.0 must deploy the TSA")
	}
	if _, err := p.Image(versions.ImageTSA); err != nil {
		t.Fatal(err)
	}
}
