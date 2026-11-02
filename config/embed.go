// Package config embeds the manifests tests read: the generated CRDs and
// RBAC, the CSV base and the samples.
package config

import "embed"

// Files holds crd/bases, rbac, manifests/bases and samples.
//
//go:embed crd/bases/*.yaml rbac/*.yaml manifests/bases/*.yaml samples/*.yaml
var Files embed.FS
