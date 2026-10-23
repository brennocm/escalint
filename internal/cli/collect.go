package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/brennocm/escalint/internal/arn"
	"github.com/brennocm/escalint/internal/buildinfo"
	"github.com/brennocm/escalint/internal/collect"
)

type collectFlags struct {
	out, profile, region, assumeFile string
	org, noExtras, quiet             bool
	resources, regions               []string
	concurrency                      int
}

func newCollectCommand() *cobra.Command {
	var f collectFlags
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect a snapshot from AWS with read-only calls",
		Long: "Collect IAM authorization details, identity providers and per-user facts with the default\n" +
			"credential chain (environment, shared config, SSO, instance role). Every call is a\n" +
			"List, Get, Describe or BatchGet; the minimal policy is docs/collector-policy.json.\n\n" +
			"--org adds the organization tree with its SCPs and RCPs (management or delegated\n" +
			"administrator account). --resources lambda,ec2,codebuild adds the compute inventory\n" +
			"used by update_code rules. --assume-roles FILE collects more accounts by assuming\n" +
			"the roles listed in FILE (one ARN per line); this switches accounts, so it is off by\n" +
			"default. The snapshot describes who can become administrator: it is written with\n" +
			"mode 0600 and must not be committed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runCollect(cmd, f) },
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.out, "output", "o", "snapshot.json", `output file ("-" for stdout)`)
	fl.StringVar(&f.profile, "profile", "", "shared config profile (default: AWS_PROFILE or default)")
	fl.StringVar(&f.region, "region", "", "region for regional calls (default: AWS_REGION or the profile's region)")
	fl.BoolVar(&f.org, "org", false, "collect the organization tree, SCPs and RCPs")
	fl.StringSliceVar(&f.resources, "resources", nil, "resource inventory: lambda, ec2, codebuild")
	fl.StringSliceVar(&f.regions, "regions", nil, "regions of the resource inventory (default: --region)")
	fl.StringVar(&f.assumeFile, "assume-roles", "", "file with one role ARN per line to collect more accounts")
	fl.BoolVar(&f.noExtras, "no-extras", false, "skip per-user access key and login profile calls (large accounts)")
	fl.IntVar(&f.concurrency, "concurrency", 8, "parallel per-user calls (1..32)")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "no progress on stderr")
	return cmd
}

// readRoleList parses --assume-roles: role ARNs, blank lines and # comments.
func readRoleList(path string) ([]string, error) {
	fh, err := os.Open(path) // #nosec G304 -- the user chose the file
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		a, err := arn.Parse(s)
		if err != nil || a.Service != "iam" || !strings.HasPrefix(a.Resource, "role/") {
			return nil, fmt.Errorf("%s:%d: %q is not a role ARN", path, line, s)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no role ARNs", path)
	}
	return out, nil
}

func runCollect(cmd *cobra.Command, f collectFlags) error {
	resources, err := collect.ParseResources(f.resources)
	if err != nil {
		return err
	}
	if f.concurrency < 1 || f.concurrency > 32 {
		return errors.New("--concurrency must be 1..32")
	}
	var roles []string
	if f.assumeFile != "" {
		if roles, err = readRoleList(f.assumeFile); err != nil {
			return err
		}
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRetryer(func() aws.Retryer { return retry.NewAdaptiveMode() }),
		awsconfig.WithRetryMaxAttempts(10),
	}
	if f.profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(f.profile))
	}
	if f.region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(f.region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return fmt.Errorf("AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1" // IAM, STS and Organizations are global
	}
	regions := f.regions
	if len(regions) == 0 {
		regions = []string{cfg.Region}
	}
	opts := collect.Options{Concurrency: f.concurrency, Extras: !f.noExtras, Version: buildinfo.Version}
	if !f.quiet {
		opts.Log = cmd.ErrOrStderr()
	}

	base := clientsFor(cfg, resources, regions, f.org)
	account, partition, err := collect.Identity(ctx, base.STS)
	if err != nil {
		return err
	}
	if !f.quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "escalint: collecting account %s with read-only calls\n", account)
	}
	first, err := collect.ReadAccount(ctx, base, account, partition, opts)
	if err != nil {
		return err
	}
	accounts := []*collect.Account{first}
	seen := map[string]bool{account: true}
	for _, roleARN := range roles {
		other := cfg.Copy()
		other.Credentials = collect.Assume(base.STS, roleARN)
		c := clientsFor(other, resources, regions, false)
		acct, _, err := collect.Identity(ctx, c.STS)
		if err != nil {
			return fmt.Errorf("--assume-roles %s: %w", roleARN, err)
		}
		if seen[acct] {
			// A snapshot lists each account once (the loader rejects
			// duplicates); the role list often includes the caller's account.
			if !f.quiet {
				fmt.Fprintf(cmd.ErrOrStderr(), "escalint: skipping %s: account %s is already collected\n", roleARN, acct)
			}
			continue
		}
		seen[acct] = true
		if !f.quiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "escalint: collecting account %s through %s\n", acct, roleARN)
		}
		a, err := collect.ReadAccount(ctx, c, acct, partition, opts)
		if err != nil {
			return err
		}
		accounts = append(accounts, a)
	}
	var org *collect.Organization
	if f.org {
		if org, err = collect.ReadOrganization(ctx, base.Organizations, opts); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(collect.NewEnvelope(partition, accounts, org, opts), "", "  ")
	if err != nil {
		return err
	}
	if err := writeAll(cmd, f.out, append(data, '\n')); err != nil {
		return err
	}
	if !f.quiet && f.out != "-" {
		fmt.Fprintf(cmd.ErrOrStderr(), "escalint: wrote %s (mode 0600); next: escalint scan %s\n", f.out, f.out)
	}
	return nil
}

func clientsFor(cfg aws.Config, resources map[string]bool, regions []string, withOrg bool) collect.Clients {
	c := collect.Clients{STS: sts.NewFromConfig(cfg), IAM: iam.NewFromConfig(cfg)}
	if withOrg {
		c.Organizations = organizations.NewFromConfig(cfg)
	}
	if len(resources) == 0 {
		return c
	}
	for _, region := range regions {
		rc := cfg.Copy()
		rc.Region = region
		r := collect.Regional{Region: region}
		if resources[collect.ResourceLambda] {
			r.Lambda = lambda.NewFromConfig(rc)
		}
		if resources[collect.ResourceEC2] {
			r.EC2, r.SSM = ec2.NewFromConfig(rc), ssm.NewFromConfig(rc)
		}
		if resources[collect.ResourceCodeBuild] {
			r.CodeBuild = codebuild.NewFromConfig(rc)
		}
		c.Regions = append(c.Regions, r)
	}
	return c
}
