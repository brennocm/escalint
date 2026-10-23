package web

import (
	"io/fs"
	"testing"
)

func TestAssetsContainsIndex(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatalf("Assets() error = %v", err)
	}
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		t.Fatalf("index.html missing (Embedded=%t): %v", Embedded, err)
	}
}
