// Package buildinfo holds version metadata injected at link time.
//
// The release build sets these variables with:
//
//	go build -ldflags "-X github.com/brennocm/escalint/internal/buildinfo.Version=v0.1.0 ..."
package buildinfo

// Values injected with -ldflags -X. They stay as plain variables (not
// constants) because the linker can only overwrite package-level string vars.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
