package diff

import (
	"errors"
	"testing"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/engine"
	"github.com/brennocm/escalint/internal/snapshot"
)

func analysisOf(t *testing.T, path string) *contract.Analysis {
	t.Helper()
	snap, err := snapshot.LoadFile(path, snapshot.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Run(snap, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := contract.Build(res, contract.Meta{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCompute(t *testing.T) {
	safe := analysisOf(t, "../rules/testdata/EL-PE-004/safe/snapshot.json")
	vuln := analysisOf(t, "../rules/testdata/EL-PE-004/vulnerable/snapshot.json")
	s, err := Compute(safe, vuln)
	if err != nil {
		t.Fatal(err)
	}
	if s.AddedPaths == 0 || s.AddedFindings == 0 || s.NewCritical == 0 || s.RemovedPaths != 0 {
		t.Errorf("summary = %+v", s)
	}
	if vuln.Diff == nil || len(vuln.Diff.Added.Paths) != s.AddedPaths {
		t.Fatalf("diff = %+v", vuln.Diff)
	}
	// The other way round, the vulnerable objects are removed and kept.
	vuln2 := analysisOf(t, "../rules/testdata/EL-PE-004/vulnerable/snapshot.json")
	safe2 := analysisOf(t, "../rules/testdata/EL-PE-004/safe/snapshot.json")
	r, err := Compute(vuln2, safe2)
	if err != nil {
		t.Fatal(err)
	}
	if r.RemovedPaths != s.AddedPaths || len(safe2.Diff.Removed.Objects.Paths) != r.RemovedPaths || len(safe2.Diff.Removed.Objects.Findings) != r.RemovedFindings {
		t.Errorf("reverse = %+v, objects %d paths", r, len(safe2.Diff.Removed.Objects.Paths))
	}
	same := analysisOf(t, "../rules/testdata/EL-PE-004/safe/snapshot.json")
	z, err := Compute(safe2, same)
	if err != nil || z != (Summary{}) {
		t.Errorf("identical inputs: %+v %v", z, err)
	}
	same.Snapshot.Redacted = true
	if _, err := Compute(safe2, same); !errors.Is(err, ErrRedacted) {
		t.Errorf("redacted: %v", err)
	}
}
