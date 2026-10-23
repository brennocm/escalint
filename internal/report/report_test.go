package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/redact"
	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/internal/synth"
)

var update = flag.Bool("update", false, "rewrite golden files")

func analysisFrom(t *testing.T, data []byte, redacted bool) *contract.Analysis {
	t.Helper()
	snap, err := snapshot.Load(bytes.NewReader(data), snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Run(snap, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	loc, err := snapshot.Locate(data)
	if err != nil {
		t.Fatal(err)
	}
	a, err := contract.Build(res, contract.Meta{Deterministic: true, Locator: loc})
	if err != nil {
		t.Fatal(err)
	}
	if redacted {
		r, err := redact.New([]byte("golden-key"))
		if err != nil {
			t.Fatal(err)
		}
		r.Analysis(a)
	}
	return a
}

func fixtures(t *testing.T) map[string][]byte {
	t.Helper()
	pe020, err := os.ReadFile("../rules/testdata/EL-PE-020/vulnerable/snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	gen, err := synth.Generate(synth.Options{Principals: 24, Seed: 42, EscalationRate: 0.25})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"modify-role": pe020, "synth": gen.JSON}
}

var extensions = map[Format]string{Text: "txt", JSON: "json", SARIF: "sarif", DOT: "dot", Mermaid: "mmd"}

func TestGoldenReports(t *testing.T) {
	for name, data := range fixtures(t) {
		for _, redacted := range []bool{false, true} {
			a := analysisFrom(t, data, redacted)
			for f, ext := range extensions {
				suffix := ""
				if redacted {
					suffix = ".redacted"
				}
				golden := filepath.Join("testdata", "golden", name+suffix+"."+ext)
				var buf bytes.Buffer
				if err := Write(&buf, a, f, Options{SnapshotURI: "snapshots/" + name + ".json"}); err != nil {
					t.Fatal(err)
				}
				if *update {
					if err := os.MkdirAll(filepath.Dir(golden), 0o750); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(golden) // #nosec G304 -- golden path
				if err != nil {
					t.Fatalf("%v (run make golden-update)", err)
				}
				if !bytes.Equal(buf.Bytes(), want) {
					t.Errorf("%s differs from golden; run make golden-update and review", golden)
				}
			}
		}
	}
}

func compileSARIF(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile("testdata/sarif-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("sarif.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSARIFValidates(t *testing.T) {
	s := compileSARIF(t)
	for name, data := range fixtures(t) {
		for _, uri := range []string{"", "snapshot.json"} {
			var buf bytes.Buffer
			if err := Write(&buf, analysisFrom(t, data, false), SARIF, Options{SnapshotURI: uri}); err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Validate(inst); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			out := buf.String()
			for _, want := range []string{`"security-severity"`, `"escalint/v1"`, `"external/attack/t1098.003"`, `"helpUri"`, `"markdown"`} {
				if !strings.Contains(out, want) {
					t.Errorf("%s: SARIF lacks %s", name, want)
				}
			}
			if (uri != "") != strings.Contains(out, `"physicalLocation"`) {
				t.Errorf("%s: physicalLocation presence wrong for uri %q", name, uri)
			}
		}
	}
}

const hostile = "evil\x1b[2J\"];\n} digraph x { <script>alert(1)</script> #`|[]{}\u202e"

func hostileAnalysis(t *testing.T) *contract.Analysis {
	t.Helper()
	a := analysisFrom(t, fixtures(t)["modify-role"], false)
	for i := range a.Nodes {
		a.Nodes[i].Name = hostile
		if a.Nodes[i].ARN != nil {
			v := "arn:aws:iam::111111111111:user/" + hostile
			a.Nodes[i].ARN = &v
		}
	}
	for i := range a.Findings {
		a.Findings[i].Message = hostile
	}
	return a
}

func TestHostileNamesAreEscaped(t *testing.T) {
	a := hostileAnalysis(t)
	var text, dot, mmd bytes.Buffer
	for f, buf := range map[Format]*bytes.Buffer{Text: &text, DOT: &dot, Mermaid: &mmd} {
		if err := Write(buf, a, f, Options{}); err != nil {
			t.Fatal(err)
		}
	}
	if strings.ContainsAny(text.String(), "\x1b\u202e") || strings.Contains(text.String(), "evil\n") {
		t.Errorf("text output carries control characters")
	}
	for _, line := range strings.Split(dot.String(), "\n") {
		if strings.Contains(line, "digraph x") && !strings.Contains(line, `\"];`) {
			t.Errorf("DOT injection: %q", line)
		}
	}
	if strings.Count(dot.String(), "digraph") != 1+strings.Count(dot.String(), "} digraph x {") {
		t.Error("DOT structure broken")
	}
	if strings.Contains(mmd.String(), "<script>") || strings.Contains(mmd.String(), `"];`) {
		t.Errorf("Mermaid output not escaped:\n%s", mmd.String())
	}
}

func TestGraphSelection(t *testing.T) {
	a := analysisFrom(t, fixtures(t)["synth"], false)
	if len(a.Paths) == 0 {
		t.Fatal("no paths")
	}
	var all, only, one bytes.Buffer
	if err := Write(&all, a, DOT, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Write(&only, a, DOT, Options{PathsOnly: true}); err != nil {
		t.Fatal(err)
	}
	if err := Write(&one, a, Mermaid, Options{PathID: a.Paths[0].ID}); err != nil {
		t.Fatal(err)
	}
	if one.Len() >= all.Len() || only.Len() >= all.Len() {
		t.Errorf("selection does not shrink output: %d %d %d", one.Len(), only.Len(), all.Len())
	}
	if err := Write(&one, a, DOT, Options{PathID: "p_missing"}); err == nil {
		t.Error("unknown path accepted")
	}
}

func TestFormats(t *testing.T) {
	if _, err := ParseFormat("sarif", ScanFormats); err != nil {
		t.Error(err)
	}
	if _, err := ParseFormat("dot", ScanFormats); err == nil {
		t.Error("dot accepted for scan")
	}
	if err := Write(&bytes.Buffer{}, &contract.Analysis{}, Format("pdf"), Options{}); err == nil {
		t.Error("pdf accepted")
	}
	var buf bytes.Buffer
	if err := Write(&buf, analysisFrom(t, fixtures(t)["modify-role"], false), Text, Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[1;31mCRITICAL\x1b[0m") {
		t.Error("color missing")
	}
	if got := ruleName("Pass a role to a new Lambda function"); got != "PassARoleToANewLambdaFunction" {
		t.Errorf("ruleName = %s", got)
	}
}
