package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	"github.com/moveeeax/r53-dangling-dns/internal/awsscan"
	"github.com/moveeeax/r53-dangling-dns/internal/core"
	"github.com/moveeeax/r53-dangling-dns/internal/report"
)

func newScanCmd() *cobra.Command {
	var (
		zone   string
		region string
		output string
		failOn string
		probe  bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Route53 zones for dangling records",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := report.ParseFormat(output)
			if err != nil {
				return err
			}
			var failThreshold core.Severity
			if failOn != "" {
				failThreshold = core.Severity(failOn)
				if !isSeverity(failThreshold) {
					return fmt.Errorf("invalid --fail-on %q (want dangling, suspicious, or ok)", failOn)
				}
			}

			ctx := context.Background()
			opts := []func(*config.LoadOptions) error{}
			if region != "" {
				opts = append(opts, config.WithRegion(region))
			}
			cfg, err := config.LoadDefaultConfig(ctx, opts...)
			if err != nil {
				return fmt.Errorf("load AWS config: %w", err)
			}
			clients := awsscan.NewClients(cfg)

			records, err := clients.ListRecords(ctx, zone)
			if err != nil {
				return err
			}
			inv, err := clients.CollectInventory(ctx)
			if err != nil {
				return err
			}

			var prober core.Prober
			if probe {
				prober = awsscan.LiveProber{}
			}
			findings := core.Scan(records, inv, prober)

			if err := report.Write(os.Stdout, format, findings); err != nil {
				return err
			}

			if failThreshold != "" && core.MaxSeverity(findings).AtLeast(failThreshold) {
				return exitError{code: 2, msg: fmt.Sprintf("findings at or above %q severity", failThreshold)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "limit the scan to a single hosted zone name")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (defaults to the resolved SDK region)")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table, json, or sarif")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero when a finding reaches this severity: dangling|suspicious|ok")
	cmd.Flags().BoolVar(&probe, "probe", false, "resolve records live and fingerprint unclaimed endpoints")
	return cmd
}

func isSeverity(s core.Severity) bool {
	switch s {
	case core.SeverityOK, core.SeveritySuspicious, core.SeverityDangling:
		return true
	default:
		return false
	}
}
