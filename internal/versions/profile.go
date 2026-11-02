// Package versions holds the product version profiles the operator supports.
package versions

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
)

// Capability is a feature a product version provides.
type Capability string

const (
	// CapabilityTSA is the RFC 3161 timestamp authority.
	CapabilityTSA Capability = "tsa"
)

// Image keys in images.env.
const (
	ImageTSA = "TSA_IMAGE"
)

// Profile describes one product version.
type Profile struct {
	// Version is the value of spec.version, such as "2.0".
	Version string
	// Images maps image keys (TSA_IMAGE, ...) to digest-pinned references.
	Images map[string]string
	// Capabilities lists what this version deploys.
	Capabilities []Capability
}

// Has reports whether the profile provides c.
func (p *Profile) Has(c Capability) bool {
	return slices.Contains(p.Capabilities, c)
}

// Image returns the reference for key, or an error if the profile has none.
func (p *Profile) Image(key string) (string, error) {
	ref, ok := p.Images[key]
	if !ok || ref == "" {
		return "", fmt.Errorf("version %s has no %s", p.Version, key)
	}
	return ref, nil
}

// RelatedImageEnv names the environment variable that overrides key for
// version, such as RELATED_IMAGE_TSA_2_0 for TSA_IMAGE in 2.0.
func RelatedImageEnv(key, version string) string {
	return "RELATED_IMAGE_" + strings.TrimSuffix(key, "_IMAGE") + "_" + strings.ReplaceAll(version, ".", "_")
}

// LoadImages parses <version>/images.env from fsys.
func LoadImages(fsys fs.FS, version string) (map[string]string, error) {
	data, err := fs.ReadFile(fsys, version+"/images.env")
	if err != nil {
		return nil, err
	}
	images := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("%s/images.env:%d: want KEY=VALUE", version, n)
		}
		if !strings.Contains(value, "@sha256:") {
			return nil, fmt.Errorf("%s/images.env:%d: %s is not pinned by digest", version, n, key)
		}
		if _, dup := images[key]; dup {
			return nil, fmt.Errorf("%s/images.env:%d: duplicate %s", version, n, key)
		}
		images[key] = value
	}
	return images, sc.Err()
}

// Set is an ordered list of profiles, oldest first.
type Set []*Profile

// Override replaces each image whose RelatedImageEnv variable lookup finds,
// so a bundle whose references a release pipeline rewrote deploys those. It
// returns the variables it used.
func (s Set) Override(lookup func(string) (string, bool)) ([]string, error) {
	var used []string
	for _, p := range s {
		for _, key := range slices.Sorted(maps.Keys(p.Images)) {
			name := RelatedImageEnv(key, p.Version)
			ref, ok := lookup(name)
			if !ok {
				continue
			}
			if !strings.Contains(ref, "@sha256:") {
				return nil, fmt.Errorf("%s=%q is not pinned by digest", name, ref)
			}
			p.Images[key] = ref
			used = append(used, name)
		}
	}
	return used, nil
}

// Lookup returns the profile for version.
func (s Set) Lookup(version string) (*Profile, bool) {
	for _, p := range s {
		if p.Version == version {
			return p, true
		}
	}
	return nil, false
}

// Versions returns the version strings in order.
func (s Set) Versions() []string {
	out := make([]string, len(s))
	for i, p := range s {
		out[i] = p.Version
	}
	return out
}

// CanMove reports whether a SecureSignPQC may go from version from to
// version to: it may stay put or move to the next version in the set.
func (s Set) CanMove(from, to string) bool {
	if from == to {
		return true
	}
	fi, ti := -1, -1
	for i, p := range s {
		switch p.Version {
		case from:
			fi = i
		case to:
			ti = i
		}
	}
	return ti >= 0 && ti == fi+1
}

// TransitionRule returns the CEL rule on spec.version that allows exactly
// the moves CanMove allows for versions: stay, or step to the next one.
func TransitionRule(versions []string) string {
	terms := []string{"self == oldSelf"}
	for i := 0; i+1 < len(versions); i++ {
		terms = append(terms, fmt.Sprintf("(oldSelf == '%s' && self == '%s')", versions[i], versions[i+1]))
	}
	return strings.Join(terms, " || ")
}
