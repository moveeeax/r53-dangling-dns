package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/r53-dangling-dns/internal/core"
)

func sample() []core.Finding {
	return []core.Finding{
		{Name: "old.example.com", Type: "CNAME", Target: "gone.us-east-1.elb.amazonaws.com",
			Zone: "example.com", Kind: "elb", Severity: core.SeverityDangling, Reason: "no load balancer"},
		{Name: "ip.example.com", Type: "A", Target: "198.51.100.7",
			Zone: "example.com", Kind: "ip", Severity: core.SeveritySuspicious, Reason: "unknown ip"},
		{Name: "app.example.com", Type: "A", Target: "my-alb.us-east-1.elb.amazonaws.com",
			Zone: "example.com", Kind: "elb", Severity: core.SeverityOK, Reason: "exists"},
	}
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"table", "json", "sarif"} {
		if _, err := ParseFormat(ok); err != nil {
			t.Fatalf("ParseFormat(%q) error: %v", ok, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestWriteTable(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatTable, sample()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"SEVERITY", "old.example.com", "1 dangling", "1 suspicious", "1 ok"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table missing %q:\n%s", want, out)
		}
	}
}

func TestWriteJSONValid(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatJSON, sample()); err != nil {
		t.Fatal(err)
	}
	var doc jsonReport
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Summary.Total != 3 || doc.Summary.Dangling != 1 {
		t.Fatalf("bad summary: %+v", doc.Summary)
	}
	if len(doc.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(doc.Findings))
	}
}

func TestWriteSARIFValid(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatSARIF, sample()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad SARIF envelope: %+v", log)
	}
	// Only the two non-ok findings become SARIF results.
	if got := len(log.Runs[0].Results); got != 2 {
		t.Fatalf("want 2 SARIF results, got %d", got)
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Fatalf("dangling should map to error, got %s", log.Runs[0].Results[0].Level)
	}
}

func TestWriteEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatJSON, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\"findings\": []") {
		t.Fatalf("empty JSON should have empty findings array:\n%s", b.String())
	}
}
