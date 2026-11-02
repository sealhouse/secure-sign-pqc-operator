package controller

import (
	"slices"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	"github.com/sealhouse/secure-sign-pqc-operator/config"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

// The CRD's spec.version enum and transition rule spell out the version list
// because markers are static.
func TestCRDVersionListMatchesProfiles(t *testing.T) {
	raw, err := config.Files.ReadFile("crd/bases/pqc.rhtas.redhat.com_securesignpqcs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	profiles, err := supported.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := profiles.Versions()

	version := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["version"]
	enum := make([]string, 0, len(version.Enum))
	for _, e := range version.Enum {
		enum = append(enum, strings.Trim(string(e.Raw), `"`))
	}
	if !slices.Equal(enum, want) {
		t.Errorf("CRD enum %v, profiles %v", enum, want)
	}

	if len(version.XValidations) != 1 {
		t.Fatalf("want one rule on spec.version, got %d", len(version.XValidations))
	}
	if got, want := version.XValidations[0].Rule, versions.TransitionRule(want); got != want {
		t.Errorf("spec.version rule\n got %s\nwant %s", got, want)
	}
}
