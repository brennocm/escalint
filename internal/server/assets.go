// Package server implements `escalint serve`. For now it only exposes the
// embedded frontend; handlers and security controls arrive in Phase 13.
package server

import (
	"fmt"
	"io/fs"

	"github.com/brennocm/escalint/web"
)

// UIAssets returns the frontend file system and fails early if index.html is
// missing (for example, a build with an empty web/dist).
func UIAssets() (fs.FS, error) {
	assets, err := web.Assets()
	if err != nil {
		return nil, err
	}
	return requireIndex(assets)
}

func requireIndex(assets fs.FS) (fs.FS, error) {
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		return nil, fmt.Errorf("embedded ui has no index.html (embedded=%t): %w", web.Embedded, err)
	}
	return assets, nil
}
