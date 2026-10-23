package report

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/redact"
	"github.com/brennocm/escalint/internal/snapshot"
	"github.com/brennocm/escalint/internal/synth"
)

// With --redact, no identifier of the snapshot appears in any output
// format (project.md Phase 7.3).
func TestPropertyRedactedReportsLeakNothing(t *testing.T) {
	runs := 30
	if raceEnabled || testing.Short() {
		runs = 6
	}
	rng := rand.New(rand.NewPCG(13, 17))
	for range runs {
		gen, err := synth.Generate(synth.Options{
			Principals: 4 + rng.IntN(27), Accounts: 1 + rng.IntN(3), Seed: rng.Uint64(),
			EscalationRate: 0.3, RandomNames: true,
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
	}
}
