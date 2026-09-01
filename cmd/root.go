// Package cmd implements the r53-dangling-dns command line.
package cmd

import (
	"github.com/spf13/cobra"
)

// version is overwritten at release time via -ldflags.
var version = "dev"

// NewRootCmd builds the root command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "r53-dangling-dns",
		Short:         "Find Route53 records that point at deprovisioned AWS resources",
		Long:          "r53-dangling-dns scans Route53 hosted zones and flags records whose backing AWS resource (ELB, CloudFront, S3, EIP) no longer exists — the classic subdomain-takeover setup.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd())
	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute() int {
	if err := NewRootCmd().Execute(); err != nil {
		if ec, ok := err.(exitError); ok {
			return ec.code
		}
		cobra.CheckErr(err)
		return 1
	}
	return 0
}

// exitError carries a specific process exit code (used by --fail-on).
type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }
