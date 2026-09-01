package core

import "testing"

func inv() Inventory {
	i := NewInventory()
	i.ELBDNSNames["my-alb-123456.us-east-1.elb.amazonaws.com"] = true
	i.CloudFrontDomains["d111111abcdef8.cloudfront.net"] = true
	i.S3Buckets["live-site"] = true
	i.PublicIPs["203.0.113.10"] = true
	return i
}

func TestClassifyELB(t *testing.T) {
	live := Classify(Record{Name: "app.example.com.", Type: "A", IsAlias: true,
		Target: "my-alb-123456.us-east-1.elb.amazonaws.com."}, inv())
	if live.Severity != SeverityOK || live.Kind != "elb" {
		t.Fatalf("live ELB: got %s/%s", live.Severity, live.Kind)
	}
	dead := Classify(Record{Name: "old.example.com.", Type: "CNAME",
		Target: "gone-lb-999.us-east-1.elb.amazonaws.com"}, inv())
	if dead.Severity != SeverityDangling {
		t.Fatalf("dead ELB should be dangling, got %s (%s)", dead.Severity, dead.Reason)
	}
}

func TestClassifyCloudFront(t *testing.T) {
	dead := Classify(Record{Name: "cdn.example.com.", Type: "CNAME",
		Target: "dGONE.cloudfront.net"}, inv())
	if dead.Severity != SeverityDangling || dead.Kind != "cloudfront" {
		t.Fatalf("dead CF: got %s/%s", dead.Severity, dead.Kind)
	}
	ok := Classify(Record{Name: "cdn.example.com.", Type: "CNAME",
		Target: "d111111abcdef8.cloudfront.net"}, inv())
	if ok.Severity != SeverityOK {
		t.Fatalf("live CF should be ok, got %s", ok.Severity)
	}
}

func TestClassifyS3Website(t *testing.T) {
	dead := Classify(Record{Name: "docs.example.com.", Type: "CNAME",
		Target: "deleted-bucket.s3-website-us-east-1.amazonaws.com"}, inv())
	if dead.Severity != SeverityDangling || dead.Kind != "s3" {
		t.Fatalf("dead S3: got %s/%s (%s)", dead.Severity, dead.Kind, dead.Reason)
	}
	ok := Classify(Record{Name: "docs.example.com.", Type: "CNAME",
		Target: "live-site.s3-website.us-east-1.amazonaws.com"}, inv())
	if ok.Severity != SeverityOK {
		t.Fatalf("live S3 should be ok, got %s (%s)", ok.Severity, ok.Reason)
	}
}

func TestClassifyARecord(t *testing.T) {
	ok := Classify(Record{Name: "ip.example.com.", Type: "A", Target: "203.0.113.10"}, inv())
	if ok.Severity != SeverityOK {
		t.Fatalf("known IP should be ok, got %s", ok.Severity)
	}
	sus := Classify(Record{Name: "ip.example.com.", Type: "A", Target: "198.51.100.7"}, inv())
	if sus.Severity != SeveritySuspicious {
		t.Fatalf("unknown IP should be suspicious, got %s", sus.Severity)
	}
}

func TestClassifyExternal(t *testing.T) {
	ext := Classify(Record{Name: "mail.example.com.", Type: "CNAME",
		Target: "ghs.googlehosted.com"}, inv())
	if ext.Severity != SeverityOK || ext.Kind != "external" {
		t.Fatalf("external target should be ok/external, got %s/%s", ext.Severity, ext.Kind)
	}
}

// fakeProber marks a fixed target as unclaimed.
type fakeProber struct{ unclaimed string }

func (p fakeProber) Probe(r Record) (bool, bool) {
	return true, normalizeHost(r.Target) == p.unclaimed
}

func TestScanProbeEscalates(t *testing.T) {
	recs := []Record{
		{Name: "docs.example.com.", Type: "CNAME", Target: "deleted-bucket.s3-website-us-east-1.amazonaws.com"},
		{Name: "ip.example.com.", Type: "A", Target: "198.51.100.7"},
	}
	// Without a prober the IP record is only suspicious.
	base := Scan(recs, inv(), nil)
	if got := Summarize(base); got.Dangling != 1 || got.Suspicious != 1 {
		t.Fatalf("base summary = %+v", got)
	}
	// With a prober flagging the IP endpoint unclaimed, it escalates to dangling.
	esc := Scan(recs, inv(), fakeProber{unclaimed: "198.51.100.7"})
	if got := Summarize(esc); got.Dangling != 2 {
		t.Fatalf("escalated summary = %+v", got)
	}
}

func TestScanSortsMostSevereFirst(t *testing.T) {
	recs := []Record{
		{Name: "b-ok.example.com.", Type: "A", Target: "203.0.113.10"},
		{Name: "a-dangling.example.com.", Type: "CNAME", Target: "gone.us-east-1.elb.amazonaws.com"},
	}
	out := Scan(recs, inv(), nil)
	if out[0].Severity != SeverityDangling {
		t.Fatalf("expected dangling first, got %s", out[0].Severity)
	}
	if MaxSeverity(out) != SeverityDangling {
		t.Fatalf("MaxSeverity = %s", MaxSeverity(out))
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityDangling.AtLeast(SeveritySuspicious) {
		t.Fatal("dangling should be >= suspicious")
	}
	if SeverityOK.AtLeast(SeverityDangling) {
		t.Fatal("ok should not be >= dangling")
	}
}
