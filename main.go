// Command r53-dangling-dns scans Route53 for records pointing at deprovisioned
// AWS resources (subdomain-takeover risk).
package main

import (
	"os"

	"github.com/moveeeax/r53-dangling-dns/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
