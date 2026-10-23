//go:build !noui

package web

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Embedded reports whether the real frontend is compiled into the binary.
const Embedded = true

// Assets returns the frontend files rooted at dist/.
func Assets() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded ui: %w", err)
	}
	return sub, nil
}
