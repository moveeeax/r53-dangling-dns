// Package report renders scan findings as a table, JSON, or SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/moveeeax/r53-dangling-dns/internal/core"
)

// Format is an output encoding.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// ParseFormat validates a format string.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatTable, FormatJSON, FormatSARIF:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown output format %q (want table, json, or sarif)", s)
	}
}

// Write renders findings in the requested format.
func Write(w io.Writer, format Format, findings []core.Finding) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, findings)
	case FormatSARIF:
		return writeSARIF(w, findings)
	default:
		return writeTable(w, findings)
	}
}

func writeTable(w io.Writer, findings []core.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "no records scanned")
		return err
	}
	// Compute column widths.
	sevW, nameW, kindW := len("SEVERITY"), len("RECORD"), len("KIND")
	for _, f := range findings {
		sevW = max(sevW, len(f.Severity))
		nameW = max(nameW, len(f.Name))
		kindW = max(kindW, len(f.Kind))
	}
	rowf := fmt.Sprintf("%%-%ds  %%-%ds  %%-%ds  %%s\n", sevW, nameW, kindW)
	if _, err := fmt.Fprintf(w, rowf, "SEVERITY", "RECORD", "KIND", "TARGET / REASON"); err != nil {
		return err
	}
	for _, f := range findings {
		detail := f.Target
		if f.Reason != "" {
			detail = f.Target + " — " + f.Reason
		}
		if _, err := fmt.Fprintf(w, rowf, string(f.Severity), f.Name, f.Kind, detail); err != nil {
			return err
		}
	}
	s := core.Summarize(findings)
	_, err := fmt.Fprintf(w, "\n%d record(s): %d dangling, %d suspicious, %d ok\n",
		s.Total, s.Dangling, s.Suspicious, s.OK)
	return err
}

// jsonReport is the top-level JSON document.
type jsonReport struct {
	Summary  core.Summary   `json:"summary"`
	Findings []core.Finding `json:"findings"`
}

func writeJSON(w io.Writer, findings []core.Finding) error {
	if findings == nil {
		findings = []core.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{Summary: core.Summarize(findings), Findings: findings})
}

// --- SARIF 2.1.0 (minimal, schema-valid) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps our severity to SARIF result levels.
func sarifLevel(s core.Severity) string {
	switch s {
	case core.SeverityDangling:
		return "error"
	case core.SeveritySuspicious:
		return "warning"
	default:
		return "note"
	}
}

func writeSARIF(w io.Writer, findings []core.Finding) error {
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "r53-dangling-dns",
				InformationURI: "https://github.com/moveeeax/r53-dangling-dns",
				Rules: []sarifRule{
					{ID: "dangling-dns", Name: "DanglingDNSRecord"},
				},
			}},
			Results: []sarifResult{},
		}},
	}
	for _, f := range findings {
		if f.Severity == core.SeverityOK {
			continue // only surface actionable findings in SARIF
		}
		msg := strings.TrimSpace(fmt.Sprintf("%s %s -> %s (%s): %s",
			f.Type, f.Name, f.Target, f.Kind, f.Reason))
		log.Runs[0].Results = append(log.Runs[0].Results, sarifResult{
			RuleID:  "dangling-dns",
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: "route53/" + f.Zone},
			}}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
