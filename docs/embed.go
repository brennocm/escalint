// Package docs embeds the rule documentation (docs/rules/*.md) so that
// `escalint rules explain` works offline from the binary.
package docs

import (
	"embed"
	"strings"
)

//go:embed rules/*.md
var rules embed.FS

// Rule returns the documentation of a rule ID.
func Rule(id string) (string, bool) {
	if strings.ContainsAny(id, "/\\.") {
		return "", false
	}
	data, err := rules.ReadFile("rules/" + id + ".md")
	if err != nil {
		return "", false
	}
	return string(data), true
}
