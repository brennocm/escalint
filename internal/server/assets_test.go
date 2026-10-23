package server

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/brennocm/escalint/web"
)

func TestUIAssetsHasIndex(t *testing.T) {
	assets, err := UIAssets()
	if err != nil {
		t.Fatalf("UIAssets() error = %v", err)
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if !web.Embedded && !strings.Contains(string(index), "-tags noui") {
		t.Errorf("noui stub should explain how to build the UI, got %q", index)
	}
}

func TestRequireIndexMissing(t *testing.T) {
	_, err := requireIndex(fstest.MapFS{"other.txt": &fstest.MapFile{}})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("requireIndex() error = %v, want fs.ErrNotExist", err)
	}
}
