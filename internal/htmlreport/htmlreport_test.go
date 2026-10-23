package htmlreport

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

const index = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>escalint</title>
    <script type="module" crossorigin src="./assets/index-1.js"></script>
    <link rel="stylesheet" crossorigin href="./assets/style-1.css">
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>`

func ui(js string) fstest.MapFS {
	return fstest.MapFS{
		"report/index.html":         &fstest.MapFile{Data: []byte(index)},
		"report/assets/index-1.js":  &fstest.MapFile{Data: []byte(js)},
		"report/assets/style-1.css": &fstest.MapFile{Data: []byte("body{color:red}")},
	}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestBuild(t *testing.T) {
	out, err := Build(ui(`const s = "</script>"; const d = "$1";`), []byte(`{"schema_version":"1","x":"`+"\\u003c/script\\u003e"+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	page := string(out)
	if strings.Contains(page, `src="./assets`) || strings.Contains(page, `href="./assets`) {
		t.Error("external references remain")
	}
	if strings.Count(page, "</script>") != 2 {
		t.Errorf("an inline script closes early:\n%s", page)
	}
	js := regexp.MustCompile(`(?s)<script type="module">(.*?)</script>`).FindStringSubmatch(page)
	css := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(page)
	if js == nil || css == nil {
		t.Fatalf("inline blocks missing:\n%s", page)
	}
	meta := regexp.MustCompile(`content="([^"]+)"`).FindStringSubmatch(page)
	if meta == nil {
		t.Fatal("no CSP meta")
	}
	csp := meta[1]
	if !strings.Contains(csp, "script-src 'sha256-"+sha(js[1])+"'") || !strings.Contains(csp, "style-src 'sha256-"+sha(css[1])+"'") {
		t.Errorf("CSP hashes do not match the inline blocks: %s", csp)
	}
	for _, want := range []string{"default-src 'none'", "connect-src 'none'", "worker-src 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %s", want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("unsafe-inline in CSP")
	}
	if !strings.Contains(page, `const d = "$1";`) {
		t.Error("bundle text altered")
	}
	if !strings.Contains(page, `<script type="application/json" id="escalint-data">{"schema_version":"1"`) {
		t.Error("data block missing")
	}
	// The data block comes before the app script, which reads it on start.
	if strings.Index(page, "escalint-data") > strings.Index(page, `<script type="module">`) {
		t.Error("data after the app script")
	}
}

func TestBuildErrors(t *testing.T) {
	if _, err := Build(fstest.MapFS{}, []byte("{}")); !errors.Is(err, ErrNoReportBuild) {
		t.Errorf("no build: %v", err)
	}
	if _, err := Build(ui("x"), []byte(`{"a":"</script>"}`)); err == nil {
		t.Error("unescaped data accepted")
	}
	bad := ui("x")
	bad["report/index.html"] = &fstest.MapFile{Data: []byte("<html></html>")}
	if _, err := Build(bad, []byte("{}")); err == nil {
		t.Error("unexpected shape accepted")
	}
	missing := ui("x")
	delete(missing, "report/assets/index-1.js")
	if _, err := Build(missing, []byte("{}")); err == nil {
		t.Error("missing script accepted")
	}
	nocss := ui("x")
	delete(nocss, "report/assets/style-1.css")
	if _, err := Build(nocss, []byte("{}")); err == nil {
		t.Error("missing style accepted")
	}
	nometa := ui("x")
	nometa["report/index.html"] = &fstest.MapFile{Data: []byte(strings.Replace(index, `<meta charset="utf-8" />`, "", 1))}
	if _, err := Build(nometa, []byte("{}")); err == nil {
		t.Error("missing charset accepted")
	}
}

func TestScriptBreakersEscaped(t *testing.T) {
	js := []byte("a='</SCRIPT>';b=/<!--/u;c=`</Script`")
	got := string(escapeScript(js))
	want := "a='<\\/SCRIPT>';b=/\\x3C!--/u;c=`<\\/Script`"
	if got != want {
		t.Errorf("escapeScript = %s, want %s", got, want)
	}
	out, err := Build(ui(string(js)), []byte(`{"schema_version":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(regexp.MustCompile(`(?i)</script`).FindAllIndex(out, -1)); n != 2 {
		t.Errorf("%d script end tags, want 2:\n%s", n, out)
	}
}
