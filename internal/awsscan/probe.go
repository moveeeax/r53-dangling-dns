package awsscan

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/moveeeax/r53-dangling-dns/internal/core"
)

// LiveProber implements core.Prober by actually resolving the record and, for
// HTTP(S) endpoints, looking for a known "unclaimed" fingerprint in the body.
// This turns a suspicious classification into a confirmed dangling one.
type LiveProber struct {
	Timeout time.Duration
}

// fingerprints are body substrings that mean the backing service is unclaimed.
var fingerprints = []string{
	"NoSuchBucket",
	"The specified bucket does not exist",
	"There isn't a GitHub Pages site here",
	"NoSuchDistribution",
}

// Probe resolves the record and fetches the endpoint over HTTPS then HTTP,
// returning (resolves, unclaimed).
func (p LiveProber) Probe(r core.Record) (bool, bool) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	host := strings.TrimSuffix(strings.TrimSpace(r.Target), ".")
	if host == "" {
		return false, false
	}
	if _, err := net.LookupHost(host); err != nil {
		// Does not resolve at all — cannot fingerprint, leave severity as-is.
		return false, false
	}
	client := &http.Client{Timeout: timeout}
	for _, scheme := range []string{"https://", "http://"} {
		resp, err := client.Get(scheme + host)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		text := string(body)
		for _, fp := range fingerprints {
			if strings.Contains(text, fp) {
				return true, true
			}
		}
	}
	return true, false
}
