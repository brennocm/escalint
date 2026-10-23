package report

import (
	"encoding/json"
	"io"

	"github.com/brennocm/escalint/internal/contract"
)

// ScanDocument is the JSON output of `escalint scan` (docs/output-json.md):
// a findings-oriented subset of analysis.json with the same objects.
type ScanDocument struct {
	SchemaVersion string                 `json:"schema_version"`
	Kind          string                 `json:"kind"`
	Generator     contract.Generator     `json:"generator"`
	Snapshot      contract.SnapshotInfo  `json:"snapshot"`
	Summary       Summary                `json:"summary"`
	Findings      []contract.Finding     `json:"findings"`
	Paths         []contract.Path        `json:"paths"`
	FixPlan       []contract.FixStep     `json:"fix_plan"`
	Suppressions  []contract.Suppression `json:"suppressions"`
	Notes         []string               `json:"notes"`
}

// Summary counts unsuppressed findings per severity.
type Summary struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
	Suppressed int `json:"suppressed"`
	Paths      int `json:"paths"`
}

// Scan builds the scan document.
func Scan(a *contract.Analysis) ScanDocument {
	c := Counts(a)
	s := Summary{Critical: c["critical"], High: c["high"], Medium: c["medium"], Low: c["low"], Info: c["info"], Paths: len(a.Paths)}
	for _, f := range a.Findings {
		if f.Suppressed != nil {
			s.Suppressed++
		}
	}
	return ScanDocument{
		SchemaVersion: contract.SchemaVersion, Kind: "escalint.scan", Generator: a.Generator, Snapshot: a.Snapshot,
		Summary: s, Findings: a.Findings, Paths: a.Paths, FixPlan: a.FixPlan, Suppressions: a.Suppressions, Notes: a.Notes,
	}
}

func writeJSON(w io.Writer, a *contract.Analysis) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Scan(a))
}
