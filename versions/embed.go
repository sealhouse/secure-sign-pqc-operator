// Package versions embeds the per-version operand image lists.
package versions

import "embed"

// FS holds <version>/images.env for every product version.
//
//go:embed */images.env
var FS embed.FS
