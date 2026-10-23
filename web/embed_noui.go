//go:build noui

package web

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed noui/index.html
var stub embed.FS

// Embedded reports whether the real frontend is compiled into the binary.
const Embedded = false

// Assets returns a single stub page explaining how to build the real UI.
func Assets() (fs.FS, error) {
	sub, err := fs.Sub(stub, "noui")
	if err != nil {
		return nil, fmt.Errorf("open noui stub: %w", err)
	}
	return sub, nil
}
