package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/brennocm/escalint/docs"
	"github.com/brennocm/escalint/internal/attack"
	"github.com/brennocm/escalint/internal/buildinfo"
	"github.com/brennocm/escalint/internal/catalog"
	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/detect"
	"github.com/brennocm/escalint/internal/diff"
	"github.com/brennocm/escalint/internal/rules"
	"github.com/brennocm/escalint/internal/synth"
	"github.com/brennocm/escalint/internal/termsafe"
	"github.com/brennocm/escalint/schema"
)

// colorAllowed honors the NO_COLOR convention (https://no-color.org).
func colorAllowed() bool { return os.Getenv("NO_COLOR") == "" }

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, build date and catalog versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat, err := catalog.Default()
			if err != nil {
				return err
			}
			att, err := attack.Default()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"escalint %s\ncommit: %s\nbuilt: %s\ngo: %s %s/%s\nanalysis schema: %s\nAWS service reference: %s (%d actions)\npathfinding.cloud: %s\nMITRE ATT&CK: %s\n",
				buildinfo.Version, buildinfo.Commit, buildinfo.Date,
				runtime.Version(), runtime.GOOS, runtime.GOARCH,
				contract.SchemaVersion, cat.Generated, cat.Len(), rules.PathfindingCommit(), att.Version)
			if err != nil {
				return fmt.Errorf("write version: %w", err)
			}
			return nil
		},
	}
}

func newSchemaCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema of analysis.json",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write(schema.AnalysisV1)
			return err
		},
	}
}

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "List and explain the rules"}
	var format string
	var withAttack bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List every rule with severity, status and category",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			att, err := attack.Default()
			if err != nil {
				return err
			}
			switch format {
			case "json":
				var out []contract.Rule
				for _, r := range rules.All() {
					out = append(out, ruleContract(r.Meta(), att))
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			case "text":
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				header := "ID\tSEVERITY\tSTATUS\tCATEGORY\tTITLE"
				if withAttack {
					header += "\tATT&CK"
				}
				fmt.Fprintln(tw, header)
				for _, r := range rules.All() {
					m := r.Meta()
					line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", m.ID, m.Severity, m.Status, m.Category, m.Title)
					if withAttack {
						var ids []string
						for _, t := range m.AttackRefs(att) {
							ids = append(ids, t.TechniqueID+" ("+strings.Join(t.Tactics, ", ")+")")
						}
						if len(ids) == 0 {
							ids = []string{"-"}
						}
						line += "\t" + strings.Join(ids, "; ")
					}
					fmt.Fprintln(tw, line)
				}
				return tw.Flush()
			}
			return fmt.Errorf("--format: %q (want text or json)", format)
		},
	}
	list.Flags().StringVarP(&format, "format", "f", "text", "output format: text, json")
	list.Flags().BoolVar(&withAttack, "attack", false, "show MITRE ATT&CK techniques and tactics")

	explain := &cobra.Command{
		Use:   "explain <rule-id>",
		Short: "Print a rule's documentation, ATT&CK techniques and CloudTrail detection hints",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, ok := rules.ByID(strings.ToUpper(args[0]))
			if !ok {
				return fmt.Errorf("unknown rule %q (see escalint rules list)", args[0])
			}
			m := r.Meta()
			doc, ok := docs.Rule(m.ID)
			if !ok {
				return fmt.Errorf("no documentation for %s", m.ID)
			}
			w := cmd.OutOrStdout()
			fmt.Fprint(w, strings.TrimRight(doc, "\n")+"\n")
			return writeExplainExtras(w, m)
		},
	}
	cmd.AddCommand(list, explain)
	return cmd
}

func ruleContract(m rules.Metadata, att *attack.Data) contract.Rule {
	r := contract.Rule{
		ID: m.ID, Title: m.Title, Category: string(m.Category), Severity: string(m.Severity), Status: string(m.Status),
		PathfindingIDs: m.PathfindingIDs, RequiredActions: m.RequiredActions, Prerequisites: m.Prerequisites,
		Remediation: m.Remediation, References: m.References, Attack: []contract.Technique{},
	}
	if m.EdgeKind != "" {
		k := string(m.EdgeKind)
		r.EdgeKind = &k
	}
	if m.AttackUnmappedReason != "" {
		reason := m.AttackUnmappedReason
		r.AttackUnmappedReason = &reason
	}
	for _, t := range m.AttackRefs(att) {
		r.Attack = append(r.Attack, contract.Technique{ID: t.TechniqueID, Name: t.Name, Tactics: t.Tactics, URL: t.URL})
	}
	return r
}

func writeExplainExtras(w io.Writer, m rules.Metadata) error {
	att, err := attack.Default()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "\n## MITRE ATT&CK")
	fmt.Fprintln(w)
	refs := m.AttackRefs(att)
	if len(refs) == 0 {
		fmt.Fprintf(w, "Not mapped: %s\n", m.AttackUnmappedReason)
	}
	for _, t := range refs {
		fmt.Fprintf(w, "- %s %s (%s): %s\n", t.TechniqueID, t.Name, strings.Join(t.Tactics, ", "), t.URL)
	}
	if m.EdgeKind == "" {
		return nil
	}
	det, err := detect.Default()
	if err != nil {
		return err
	}
	step := det.ForStep(string(m.EdgeKind), m.RequiredActions)
	fmt.Fprintln(w, "\n## Detection (CloudTrail)")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Visibility: %s (%s).\n\n", step.Visibility, step.Status)
	if len(step.Events) == 0 {
		fmt.Fprintln(w, "No CloudTrail event records this step.")
	}
	for _, e := range step.Events {
		fmt.Fprintf(w, "- `%s` from `%s` (%s event); key fields: %s. %s\n", e.Name, e.Source, e.Kind, strings.Join(e.KeyFields, ", "), e.Region)
	}
	if step.RequiresDataEvents {
		fmt.Fprintln(w, "\nPart of this step is only visible with CloudTrail data events enabled.")
	}
	if len(step.BlindSpots) > 0 {
		fmt.Fprintln(w, "\nBlind spots:")
		for _, b := range step.BlindSpots {
			fmt.Fprintf(w, "- %s\n", b)
		}
	}
	return nil
}

func newAttackCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "attack", Short: "MITRE ATT&CK views of the rule catalog"}
	var f analysisFlags
	var format string
	coverage := &cobra.Command{
		Use:   "coverage [snapshot|analysis.json]",
		Short: "List the ATT&CK techniques the rules detect (and, with an input, those it exhibits)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			att, err := attack.Default()
			if err != nil {
				return err
			}
			byTech := map[string][]string{}
			for _, r := range rules.All() {
				for _, t := range r.Meta().Attack {
					byTech[t] = append(byTech[t], r.Meta().ID)
				}
			}
			exhibited := map[string]contract.TechniqueCount{}
			if len(args) == 1 {
				l, err := f.load(cmd, args[0])
				if err != nil {
					return err
				}
				for _, t := range l.analysis.Attack.Techniques {
					exhibited[t.ID] = t
				}
			}
			ids := make([]string, 0, len(byTech))
			for id := range byTech {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			type row struct {
				ID       string   `json:"id"`
				Name     string   `json:"name"`
				Tactics  []string `json:"tactics"`
				Rules    []string `json:"rules"`
				Findings int      `json:"findings"`
				Paths    int      `json:"paths"`
			}
			var rows []row
			for _, id := range ids {
				t, _ := att.Lookup(id)
				rows = append(rows, row{ID: id, Name: t.Name, Tactics: t.Tactics, Rules: byTech[id], Findings: exhibited[id].Findings, Paths: exhibited[id].Paths})
			}
			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"attack_version": att.Version, "techniques": rows})
			}
			if format != "text" {
				return fmt.Errorf("--format: %q (want text or json)", format)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			header := "TECHNIQUE\tNAME\tTACTICS\tRULES"
			if len(args) == 1 {
				header += "\tFINDINGS\tPATHS"
			}
			fmt.Fprintln(tw, header)
			for _, r := range rows {
				line := fmt.Sprintf("%s\t%s\t%s\t%s", r.ID, r.Name, strings.Join(r.Tactics, ", "), strings.Join(r.Rules, ","))
				if len(args) == 1 {
					line += fmt.Sprintf("\t%d\t%d", r.Findings, r.Paths)
				}
				fmt.Fprintln(tw, line)
			}
			fmt.Fprintf(tw, "\nMITRE ATT&CK %s. ATT&CK is a registered trademark of The MITRE Corporation.\n", att.Version)
			return tw.Flush()
		},
	}
	f.register(coverage)
	coverage.Flags().StringVarP(&format, "format", "f", "text", "output format: text, json")
	cmd.AddCommand(coverage)
	return cmd
}

func newSynthCommand() *cobra.Command {
	var o synth.Options
	var out string
	cmd := &cobra.Command{
		Use:    "synth",
		Short:  "Generate a synthetic snapshot (development and benchmarks)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := synth.Generate(o)
			if err != nil {
				return err
			}
			return writeAll(cmd, out, res.JSON)
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&o.Principals, "principals", 50, "users, groups and roles per account")
	fl.IntVar(&o.Accounts, "accounts", 1, "number of accounts (1..9)")
	fl.Uint64Var(&o.Seed, "seed", 1, "random seed")
	fl.Float64Var(&o.EscalationRate, "escalation-rate", 0.1, "share of principals with a planted escalation primitive")
	fl.BoolVar(&o.RandomNames, "random-names", false, "random identifiers instead of word-based names")
	fl.StringVarP(&out, "output", "o", "", "write to a file (mode 0600) instead of stdout")
	return cmd
}

func writeDiffText(w io.Writer, a *contract.Analysis, s diff.Summary) error {
	fmt.Fprintf(w, "paths: +%d -%d\nfindings: +%d -%d (%d new critical)\nedges: +%d -%d\n",
		s.AddedPaths, s.RemovedPaths, s.AddedFindings, s.RemovedFindings, s.NewCritical, s.AddedEdges, s.RemovedEdges)
	added := map[string]bool{}
	for _, id := range a.Diff.Added.Findings {
		added[id] = true
	}
	if s.AddedFindings > 0 {
		fmt.Fprintln(w, "\nAdded findings")
		for _, f := range a.Findings {
			if added[f.ID] {
				fmt.Fprintf(w, "  + %s %s %s\n", strings.ToUpper(f.Severity), f.RuleID, termsafe.Line(f.Message))
			}
		}
	}
	if s.RemovedFindings > 0 {
		fmt.Fprintln(w, "\nRemoved findings")
		for _, f := range a.Diff.Removed.Objects.Findings {
			fmt.Fprintf(w, "  - %s %s %s\n", strings.ToUpper(f.Severity), f.RuleID, termsafe.Line(f.Message))
		}
	}
	return nil
}
