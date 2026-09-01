// Package core holds the provider-agnostic domain model and classification
// logic for r53-dangling-dns. It has no AWS SDK dependency so it can be unit
// tested without credentials or network access.
package core

import (
	"sort"
	"strings"
)

// Severity ranks a finding from safe to exploitable.
type Severity string

const (
	// SeverityOK means the record points at a backing resource we confirmed exists.
	SeverityOK Severity = "ok"
	// SeveritySuspicious means the record points at an AWS-shaped endpoint we
	// could not confirm against inventory (needs a human look).
	SeveritySuspicious Severity = "suspicious"
	// SeverityDangling means the backing AWS resource is confirmed gone: the
	// subdomain is takeover-prone.
	SeverityDangling Severity = "dangling"
)

// rank gives a total order so we can sort/compare severities.
var rank = map[Severity]int{SeverityOK: 0, SeveritySuspicious: 1, SeverityDangling: 2}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return rank[s] >= rank[min] }

// Record is a single Route53 resource record set target, flattened to one value.
type Record struct {
	Zone    string // hosted zone name, e.g. "example.com."
	Name    string // record name, e.g. "app.example.com."
	Type    string // A, AAAA, CNAME
	IsAlias bool   // true for Route53 ALIAS records
	Target  string // alias DNS name, CNAME value, or A/AAAA IP address
}

// Inventory is the set of live AWS resources in the account, used to decide
// whether a record's target still has a backing resource.
type Inventory struct {
	ELBDNSNames       map[string]bool // load balancer DNS names (v2 + classic), lowercased
	CloudFrontDomains map[string]bool // distribution domain names, lowercased
	S3Buckets         map[string]bool // bucket names
	PublicIPs         map[string]bool // account-owned public IPv4/IPv6 (EIPs + instance IPs)
}

// NewInventory returns an Inventory with all sets initialized.
func NewInventory() Inventory {
	return Inventory{
		ELBDNSNames:       map[string]bool{},
		CloudFrontDomains: map[string]bool{},
		S3Buckets:         map[string]bool{},
		PublicIPs:         map[string]bool{},
	}
}

// Finding is the classified result for one record.
type Finding struct {
	Record   Record   `json:"-"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Target   string   `json:"target"`
	Zone     string   `json:"zone"`
	Kind     string   `json:"kind"`     // elb, cloudfront, s3, ip, external
	Severity Severity `json:"severity"` // ok, suspicious, dangling
	Reason   string   `json:"reason"`
}

// targetKind identifies which AWS service (if any) an endpoint belongs to.
type targetKind int

const (
	kindExternal targetKind = iota
	kindELB
	kindCloudFront
	kindS3
	kindIP
)

// classifyKind inspects a normalized (lowercased, dot-stripped) hostname and
// returns the AWS service kind plus, for S3, the bucket name. A plain (non-alias)
// A/AAAA record holds a literal IP; an ALIAS A/AAAA record holds a hostname and
// is matched like a CNAME.
func classifyKind(target, rtype string, isAlias bool) (targetKind, string) {
	t := normalizeHost(target)
	if (rtype == "A" || rtype == "AAAA") && !isAlias {
		return kindIP, ""
	}
	switch {
	case strings.Contains(t, ".cloudfront.net"):
		return kindCloudFront, ""
	case strings.Contains(t, ".elb.amazonaws.com"):
		return kindELB, ""
	case strings.Contains(t, "s3-website") && strings.Contains(t, "amazonaws.com"):
		return kindS3, bucketFromS3Host(t)
	case strings.Contains(t, ".s3.amazonaws.com") || strings.Contains(t, ".s3-") && strings.Contains(t, ".amazonaws.com"):
		return kindS3, bucketFromS3Host(t)
	default:
		return kindExternal, ""
	}
}

// bucketFromS3Host pulls the bucket label out of an S3 website/REST endpoint.
// "my-site.s3-website-us-east-1.amazonaws.com" -> "my-site".
func bucketFromS3Host(host string) string {
	i := strings.Index(host, ".s3")
	if i <= 0 {
		return ""
	}
	return host[:i]
}

// normalizeHost lowercases and strips a trailing dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// Classify decides a single record's severity against the live inventory.
func Classify(r Record, inv Inventory) Finding {
	f := Finding{
		Record: r,
		Name:   normalizeHost(r.Name),
		Type:   r.Type,
		Target: normalizeHost(r.Target),
		Zone:   normalizeHost(r.Zone),
	}
	kind, bucket := classifyKind(r.Target, r.Type, r.IsAlias)
	switch kind {
	case kindELB:
		f.Kind = "elb"
		if inv.ELBDNSNames[f.Target] {
			f.Severity, f.Reason = SeverityOK, "load balancer exists"
		} else {
			f.Severity, f.Reason = SeverityDangling, "no load balancer with this DNS name in the account"
		}
	case kindCloudFront:
		f.Kind = "cloudfront"
		if inv.CloudFrontDomains[f.Target] {
			f.Severity, f.Reason = SeverityOK, "distribution exists"
		} else {
			f.Severity, f.Reason = SeverityDangling, "no CloudFront distribution with this domain in the account"
		}
	case kindS3:
		f.Kind = "s3"
		if bucket != "" && inv.S3Buckets[bucket] {
			f.Severity, f.Reason = SeverityOK, "bucket "+bucket+" exists"
		} else {
			f.Severity, f.Reason = SeverityDangling, "no S3 bucket named "+bucket+" in the account"
		}
	case kindIP:
		f.Kind = "ip"
		if inv.PublicIPs[f.Target] {
			f.Severity, f.Reason = SeverityOK, "address is allocated in the account"
		} else {
			f.Severity, f.Reason = SeveritySuspicious, "address not found among account EIPs/instance IPs; verify it is still yours"
		}
	default:
		f.Kind = "external"
		f.Severity, f.Reason = SeverityOK, "target is not an AWS-native endpoint"
	}
	return f
}

// Prober optionally checks whether a record actually resolves and whether the
// live endpoint returns a known "unclaimed" fingerprint (e.g. NoSuchBucket).
type Prober interface {
	// Probe returns (resolves, unclaimed). unclaimed=true escalates severity.
	Probe(r Record) (resolves bool, unclaimed bool)
}

// Scan classifies every record against inventory. When a Prober is supplied,
// an "unclaimed" fingerprint escalates a suspicious finding to dangling, and a
// confirmed fingerprint reinforces a dangling one.
func Scan(records []Record, inv Inventory, prober Prober) []Finding {
	out := make([]Finding, 0, len(records))
	for _, r := range records {
		f := Classify(r, inv)
		if prober != nil && f.Severity != SeverityOK {
			if _, unclaimed := prober.Probe(r); unclaimed {
				f.Severity = SeverityDangling
				f.Reason += "; live endpoint returned an unclaimed fingerprint"
			}
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] > rank[out[j].Severity] // most severe first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Summary counts findings by severity.
type Summary struct {
	OK         int `json:"ok"`
	Suspicious int `json:"suspicious"`
	Dangling   int `json:"dangling"`
	Total      int `json:"total"`
}

// Summarize tallies a slice of findings.
func Summarize(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		s.Total++
		switch f.Severity {
		case SeverityOK:
			s.OK++
		case SeveritySuspicious:
			s.Suspicious++
		case SeverityDangling:
			s.Dangling++
		}
	}
	return s
}

// MaxSeverity returns the highest severity present, or SeverityOK for none.
func MaxSeverity(findings []Finding) Severity {
	max := SeverityOK
	for _, f := range findings {
		if rank[f.Severity] > rank[max] {
			max = f.Severity
		}
	}
	return max
}
