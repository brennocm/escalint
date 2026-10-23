package report

import (
	"encoding/json"
	"io"
	"strings"
	"unicode"

	"github.com/brennocm/escalint/docs"
	"github.com/brennocm/escalint/internal/contract"
)

// SARIF 2.1.0 output (ADR 0011). Only the properties escalint fills are
// modeled.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	repoURL      = "https://github.com/brennocm/escalint"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
	ColumnKind  string            `json:"columnKind"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	HelpURI              string         `json:"helpUri"`
	Help                 sarifHelp      `json:"help"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// SecuritySeverity maps severities to the numeric scores GitHub code
// scanning uses for its severity labels.
var SecuritySeverity = map[string]string{
	"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0",
}

func level(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// ruleName turns a title into a SARIF rule name ("PassARoleToANewLambda…").
func ruleName(title string) string {
	var b strings.Builder
	for _, w := range strings.FieldsFunc(title, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		b.WriteString(string(r))
	}
	return b.String()
}

func writeSARIF(w io.Writer, a *contract.Analysis, opts Options) error {
	driver := sarifDriver{Name: "escalint", Version: a.Generator.Version, InformationURI: repoURL, Rules: []sarifRule{}}
	ruleIndex := map[string]int{}
	for _, r := range a.Rules {
		tags := []string{"security", "iam", r.Category}
		for _, t := range r.Attack {
			tags = append(tags, "external/attack/"+strings.ToLower(t.ID))
		}
		for _, ref := range r.References {
			if id, ok := strings.CutPrefix(ref, "https://cwe.mitre.org/data/definitions/"); ok {
				tags = append(tags, "external/cwe/cwe-"+strings.TrimSuffix(id, ".html"))
			}
		}
		precision := "high"
		if r.Status == "experimental" {
			precision = "medium"
		}
		md, ok := docs.Rule(r.ID)
		if !ok {
			md = "# " + r.Title + "\n\n" + r.Remediation + "\n"
		}
		ruleIndex[r.ID] = len(driver.Rules)
		driver.Rules = append(driver.Rules, sarifRule{
			ID: r.ID, Name: ruleName(r.Title),
			ShortDescription:     sarifText{Text: r.Title},
			FullDescription:      sarifText{Text: r.Title + ". " + r.Remediation},
			HelpURI:              repoURL + "/blob/main/docs/rules/" + r.ID + ".md",
			Help:                 sarifHelp{Text: r.Title + "\n\nRemediation: " + r.Remediation, Markdown: md},
			DefaultConfiguration: sarifConfig{Level: level(r.Severity)},
			Properties: map[string]any{
				"security-severity": SecuritySeverity[r.Severity],
				"tags":              tags,
				"precision":         precision,
				"problem.severity":  level(r.Severity),
			},
		})
	}
	ix := newIndex(a)
	results := []sarifResult{}
	for _, f := range a.Findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			continue // findings of rules outside the document cannot be described
		}
		loc := sarifLocation{}
		if opts.SnapshotURI != "" {
			line := 1
			if f.Location.Line != nil {
				line = *f.Location.Line
			}
			loc.PhysicalLocation = &sarifPhysical{ArtifactLocation: sarifArtifact{URI: opts.SnapshotURI}, Region: sarifRegion{StartLine: line}}
		}
		seen := map[string]bool{}
		addLogical := func(name, kind string) {
			if name != "" && !seen[name] {
				seen[name] = true
				loc.LogicalLocations = append(loc.LogicalLocations, sarifLogical{FullyQualifiedName: name, Kind: kind})
			}
		}
		if f.NodeID != nil {
			addLogical(ix.label(*f.NodeID), "resource")
		}
		addLogical(f.Location.Entity, "resource")
		if f.Location.Policy != "" {
			addLogical(f.Location.Policy, "object")
		}
		msg := f.Message
		if f.Remediation != "" {
			msg += ". Fix: " + f.Remediation
		}
		props := map[string]any{"severity": f.Severity, "latent": f.Latent}
		if f.PathID != nil {
			props["path_id"] = *f.PathID
		}
		if f.EdgeID != nil {
			props["edge_id"] = *f.EdgeID
		}
		res := sarifResult{
			RuleID: f.RuleID, RuleIndex: idx, Level: level(f.Severity), Message: sarifText{Text: msg},
			Locations:           []sarifLocation{loc},
			PartialFingerprints: map[string]string{"escalint/v1": f.ID},
			Properties:          props,
		}
		if f.Suppressed != nil {
			res.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: f.Suppressed.Reason}}
		}
		results = append(results, res)
	}
	log := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{{
		Tool: sarifTool{Driver: driver}, Invocations: []sarifInvocation{{ExecutionSuccessful: true}},
		Results: results, ColumnKind: "utf16CodeUnits",
		Properties: map[string]any{"redacted": a.Snapshot.Redacted, "paths": len(a.Paths)},
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
