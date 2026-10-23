package graph

import (
	"bytes"
	"os"
	"testing"

	"github.com/brennocm/escalint/internal/snapshot"
)

// FuzzBuild runs arbitrary snapshots through loading and graph construction:
// nothing may panic, and IDs must stay consistent with adjacency.
func FuzzBuild(f *testing.F) {
	for _, name := range []string{"../snapshot/testdata/authz-cli.json", "../snapshot/testdata/envelope.json"} {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(testSnapshot))
	f.Fuzz(func(t *testing.T, data []byte) {
		snap, err := snapshot.Load(bytes.NewReader(data), snapshot.Options{MaxBytes: 1 << 20, MaxPrincipals: 200})
		if err != nil {
			return
		}
		g, _ := Build(snap, Options{Now: buildTime})
		for _, e := range g.Edges() {
			if g.Node(e.From) == nil || g.Node(e.To) == nil {
				t.Fatalf("edge %s has a dangling endpoint", e.ID)
			}
			if e.ID != EdgeID(e.From, e.To, e.Kind) {
				t.Fatalf("edge ID mismatch")
			}
		}
	})
}
