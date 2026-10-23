// Package suppress applies the suppressions and groupings of .escalint.yaml
// to an analysis. Suppressed findings are marked, never removed: JSON, SARIF
// and the UI still show them with the justification. A suppression without
// a reason suppresses nothing and is itself reported (EL-PARSE-003); an
// expired one stops suppressing.
package suppress

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/brennocm/escalint/internal/config"
	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/graph"
	"github.com/brennocm/escalint/internal/match"
	"github.com/brennocm/escalint/internal/rules"
)

// RuleUnjustified is the rule ID of findings about unjustified suppressions.
const RuleUnjustified = "EL-PARSE-003"

// Statuses of a suppression.
const (
	Active      = "active"
	Expired     = "expired"
	Unjustified = "unjustified"
)

// Apply marks the findings matched by the configuration's suppressions and
// fills a.Suppressions. now decides expiry.
func Apply(a *contract.Analysis, f *config.File, now time.Time) {
	if f == nil {
		return
	}
	arnOf := map[string]string{}
	for _, n := range a.Nodes {
		if n.ARN != nil {
			arnOf[n.ID] = *n.ARN
		}
	}
	subject := func(fd contract.Finding) string {
		if fd.NodeID != nil && arnOf[*fd.NodeID] != "" {
			return arnOf[*fd.NodeID]
		}
		return fd.Location.Entity
	}
	source := f.Source
	if source == "" {
		source = config.DefaultName
	}
	var extra []contract.Finding
	for i, s := range f.Suppressions {
		entry := contract.Suppression{Rule: s.Rule, ARN: s.ARN, Reason: s.Reason, Status: Active, Findings: []string{}}
		if s.Expires != "" {
			exp := s.Expires
			entry.Expires = &exp
		}
		switch {
		case strings.TrimSpace(s.Reason) == "":
			entry.Status = Unjustified
		case s.Expired(now):
			entry.Status = Expired
		}
		ref := fmt.Sprintf("%s#suppressions[%d]", source, i)
		for j := range a.Findings {
			fd := &a.Findings[j]
			if fd.RuleID == RuleUnjustified || !match.Glob(s.Rule, fd.RuleID) || !match.Glob(s.ARN, subject(*fd)) {
				continue
			}
			entry.Findings = append(entry.Findings, fd.ID)
			if entry.Status == Active && fd.Suppressed == nil {
				fd.Suppressed = &contract.Suppressed{Reason: s.Reason, Expires: entry.Expires, Source: ref}
			}
		}
		sort.Strings(entry.Findings)
		a.Suppressions = append(a.Suppressions, entry)
		if entry.Status == Unjustified {
			meta := unjustifiedMeta()
			extra = append(extra, contract.Finding{
				ID:       "f_" + strings.TrimPrefix(graph.PathID([]string{RuleUnjustified, ref, s.Rule, s.ARN}), "p_"),
				RuleID:   RuleUnjustified,
				Severity: string(meta.Severity),
				Title:    meta.Title,
				Message: fmt.Sprintf("suppression %s (rule %s, arn %s) has no reason, so it suppresses none of its %d finding(s)",
					ref, s.Rule, s.ARN, len(entry.Findings)),
				Location:    contract.Location{Policy: source, StatementIndex: -1, Path: fmt.Sprintf("suppressions[%d]", i)},
				Remediation: meta.Remediation,
			})
		}
	}
	a.Findings = append(a.Findings, extra...)
	sortFindings(a.Findings)
	a.Stats.Findings = len(a.Findings)
}

func unjustifiedMeta() rules.Metadata {
	r, _ := rules.ByID(RuleUnjustified)
	return r.Meta()
}

func sortFindings(list []contract.Finding) {
	rank := func(s string) int {
		sev, _ := rules.ParseSeverity(s)
		return sev.Rank()
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		switch {
		case rank(a.Severity) != rank(b.Severity):
			return rank(a.Severity) < rank(b.Severity)
		case a.RuleID != b.RuleID:
			return a.RuleID < b.RuleID
		default:
			return a.ID < b.ID
		}
	})
}

// Group assigns UI groupings: each node gets the first grouping whose ARN
// patterns match it.
func Group(a *contract.Analysis, f *config.File) {
	if f == nil {
		return
	}
	members := map[string][]string{}
	for i := range a.Nodes {
		n := &a.Nodes[i]
		if n.ARN == nil {
			continue
		}
	groups:
		for _, g := range f.Groupings {
			for _, p := range g.ARNs {
				if match.Glob(p, *n.ARN) {
					name := g.Name
					n.Group = &name
					members[g.Name] = append(members[g.Name], n.ID)
					break groups
				}
			}
		}
	}
	for _, g := range f.Groupings {
		ids := members[g.Name]
		sort.Strings(ids)
		if ids == nil {
			ids = []string{}
		}
		a.Groupings = append(a.Groupings, contract.Grouping{Name: g.Name, Nodes: ids})
	}
}
