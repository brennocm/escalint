package report

import (
	"bytes"
	"testing"

	"pgregory.net/rapid"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/redact"
	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/internal/synth"
)

// With --redact, no identifier of the snapshot appears in any output
// format (project.md Phase 7.3).
func TestPropertyRedactedReportsLeakNothing(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		gen, err := synth.Generate(synth.Options{
			Principals:     rapid.IntRange(4, 30).Draw(t, "principals"),
			Accounts:       rapid.IntRange(1, 3).Draw(t, "accounts"),
			Seed:           rapid.Uint64().Draw(t, "seed"),
			EscalationRate: 0.3,
			RandomNames:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := snapshot.Load(bytes.NewReader(gen.JSON), snapshot.Options{})
		if err != nil {
			t.Fatal(err)
		}
		res, err := engine.Run(snap, engine.Options{Experimental: true})
		if err != nil {
			t.Fatal(err)
		}
		loc, err := snapshot.Locate(gen.JSON)
		if err != nil {
			t.Fatal(err)
		}
		a, err := contract.Build(res, contract.Meta{Locator: loc})
		if err != nil {
			t.Fatal(err)
		}
		r, err := redact.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Analysis(a)
		outputs := map[string][]byte{}
		doc, err := contract.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		outputs["analysis.json"] = doc
		for f := range extensions {
			var buf bytes.Buffer
			if err := Write(&buf, a, f, Options{SnapshotURI: "snapshot.json"}); err != nil {
				t.Fatal(err)
			}
			outputs[string(f)] = buf.Bytes()
		}
		for name, out := range outputs {
			for _, id := range gen.Identifiers {
				if bytes.Contains(out, []byte(id)) {
					t.Fatalf("%s output contains identifier %q", name, id)
				}
			}
		}
	})
}
