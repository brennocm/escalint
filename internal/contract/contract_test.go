package contract

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/schema"
)

var update = flag.Bool("update", false, "rewrite golden files")

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.AnalysisV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("analysis.v1.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("analysis.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, data []byte) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(inst); err != nil {
		t.Fatalf("schema validation: %v", err)
	}
}

func analyze(t *testing.T, path string, opts engine.Options) []byte {
	t.Helper()
	snap, err := snapshot.LoadFile(path, snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Run(snap, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	loc, err := snapshot.Locate(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Build(res, Meta{Deterministic: true, Locator: loc})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var goldens = map[string]string{
	"passrole-lambda": "../rules/testdata/EL-PE-022/vulnerable/snapshot.json",
	"modify-role":     "../rules/testdata/EL-PE-020/vulnerable/snapshot.json",
	"diagnostics":     "../snapshot/testdata/authz-diagnostics.json",
	"envelope":        "../snapshot/testdata/envelope.json",
}

func TestGoldenAnalyses(t *testing.T) {
	s := compileSchema(t)
	for name, src := range goldens {
		t.Run(name, func(t *testing.T) {
			got := analyze(t, src, engine.Options{Experimental: true})
			validate(t, s, got)
			golden := filepath.Join("testdata", name+".analysis.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/contract -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from golden; run make golden-update and review the diff", golden)
			}
			validate(t, s, want)
		})
	}
}

// Every rule fixture produces a valid document.
func TestAllFixturesValidate(t *testing.T) {
	s := compileSchema(t)
	paths, err := filepath.Glob("../rules/testdata/*/*/snapshot.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("fixtures: %v", err)
	}
	for _, p := range paths {
		validate(t, s, analyze(t, p, engine.Options{Experimental: true}))
	}
}

func TestDurationOnlyWhenNotDeterministic(t *testing.T) {
	snap, err := snapshot.LoadFile(goldens["modify-role"], snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Run(snap, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Build(res, Meta{Duration: 1500000})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["stats"].(map[string]any)["duration_ms"]; !ok {
		t.Error("duration_ms missing")
	}
	validate(t, compileSchema(t), data)
}

// The schema rejects unknown fields, so struct and schema cannot drift.
func TestSchemaRejectsUnknownField(t *testing.T) {
	s := compileSchema(t)
	data := analyze(t, goldens["modify-role"], engine.Options{})
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["surprise"] = true
	bad, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	if s.Validate(inst) == nil {
		t.Error("unknown field accepted")
	}
}
