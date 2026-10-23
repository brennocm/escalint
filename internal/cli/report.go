package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/htmlreport"
	"github.com/brennocm/escalint/web"
)

func newReportCommand() *cobra.Command {
	var f analysisFlags
	var out string
	var html bool
	cmd := &cobra.Command{
		Use:   "report --html <snapshot|analysis.json> -o report.html",
		Short: "Write a single self-contained HTML file with the UI and the analysis",
		Long: "Write one HTML file that opens offline (file://) with every view: the UI, its fonts and the\n" +
			"analysis are inlined, and a Content-Security-Policy allows only those inline blocks (by\n" +
			"hash). The file shows who can become administrator: use --redact before sharing it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !html {
				return errors.New("only --html is supported")
			}
			l, err := f.load(cmd, args[0])
			if err != nil {
				return err
			}
			if err := f.finish(l); err != nil {
				return err
			}
			data, err := contract.Marshal(l.analysis)
			if err != nil {
				return err
			}
			assets, err := web.Assets()
			if err != nil {
				return err
			}
			page, err := htmlreport.Build(assets, data)
			if err != nil {
				return err
			}
			if err := writeAll(cmd, out, page); err != nil {
				return err
			}
			if !l.analysis.Snapshot.Redacted {
				f.note(cmd, "the report names principals and accounts; generate it with --redact before sharing")
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&html, "html", false, "write a single-file HTML report")
	cmd.Flags().StringVarP(&out, "output", "o", "escalint-report.html", `output file ("-" for stdout)`)
	return cmd
}
