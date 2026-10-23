// Package htmlreport builds the single-file HTML report: the report build
// of the web UI (web/dist/report), its JavaScript and CSS inlined, the
// analysis embedded as a JSON data block, and a Content-Security-Policy
// meta tag that allows exactly those inline blocks by SHA-256 hash, never
// 'unsafe-inline' (ADR 0018).
package htmlreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// ErrNoReportBuild is returned when the binary has no report build of the UI.
var ErrNoReportBuild = errors.New("this escalint was built without the web UI (report/index.html missing); rebuild with make web-build build")

var (
	scriptTag = regexp.MustCompile(`<script type="module" crossorigin src="\./([^"]+\.js)"></script>`)
	styleTag  = regexp.MustCompile(`<link rel="stylesheet" crossorigin href="\./([^"]+\.css)">`)
	// Inside an inline <script>, "</script" in any case ends the element and
	// "<!--" can switch the HTML parser into a state where the real end tag
	// no longer closes it. Both are escaped: "<\/" and "\x3C" mean "</" and
	// "<" in JavaScript strings, templates and regular expressions (also with
	// the u flag); in a module script they cannot appear outside those.
	scriptBreak = regexp.MustCompile(`(?i)</(script)|<!--`)
	styleEnd    = regexp.MustCompile(`(?i)</(style)`)
)

func escapeScript(js []byte) []byte {
	return scriptBreak.ReplaceAllFunc(js, func(m []byte) []byte {
		if string(m) == "<!--" {
			return []byte(`\x3C!--`)
		}
		return append([]byte(`<\/`), m[2:]...)
	})
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// CSP returns the policy of a report whose inline script and style are js
// and css.
func CSP(js, css []byte) string {
	return "default-src 'none'; script-src " + hash(js) + "; style-src " + hash(css) +
		"; img-src data: blob:; font-src data:; connect-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'"
}

// Build returns the report HTML. ui is the embedded UI file system (with
// report/index.html); analysis is the analysis.json document, which must
// escape '<' (contract.Marshal does).
func Build(ui fs.FS, analysis []byte) ([]byte, error) {
	index, err := fs.ReadFile(ui, "report/index.html")
	if err != nil {
		return nil, ErrNoReportBuild
	}
	if bytes.Contains(analysis, []byte("</")) {
		return nil, errors.New("htmlreport: analysis JSON must escape '<'")
	}
	page := string(index)
	sm := scriptTag.FindStringSubmatch(page)
	cm := styleTag.FindStringSubmatch(page)
	if sm == nil || cm == nil {
		return nil, errors.New("htmlreport: report/index.html has an unexpected shape (no module script or stylesheet)")
	}
	js, err := fs.ReadFile(ui, path.Join("report", sm[1]))
	if err != nil {
		return nil, fmt.Errorf("htmlreport: %w", err)
	}
	css, err := fs.ReadFile(ui, path.Join("report", cm[1]))
	if err != nil {
		return nil, fmt.Errorf("htmlreport: %w", err)
	}
	js = escapeScript(js)
	css = styleEnd.ReplaceAll(css, []byte(`<\/$1`))
	// Literal replacement (strings.Replace, not regexp) so '$' in the
	// bundle stays as is.
	page = strings.Replace(page, sm[0], "", 1)
	page = strings.Replace(page, cm[0], "<style>"+string(css)+"</style>", 1)
	meta := `<meta http-equiv="Content-Security-Policy" content="` + CSP(js, css) + `" />`
	page = strings.Replace(page, `<meta charset="utf-8" />`, `<meta charset="utf-8" />`+"\n    "+meta, 1)
	body := `<script type="application/json" id="escalint-data">` + string(analysis) + "</script>\n    " +
		`<script type="module">` + string(js) + "</script>\n  </body>"
	page = strings.Replace(page, "</body>", body, 1)
	if !strings.Contains(page, meta) || !strings.Contains(page, `id="escalint-data"`) {
		return nil, errors.New("htmlreport: report/index.html has no charset meta or body")
	}
	return []byte(page), nil
}
