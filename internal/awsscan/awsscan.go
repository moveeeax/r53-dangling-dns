// Package awsscan wires the AWS SDK v2 to the provider-agnostic core: it reads
// Route53 records and collects live-resource inventory. It is intentionally thin
// so the interesting logic stays in package core (which is unit tested without
// AWS). All calls here are read-only (List/Describe/Get).
package awsscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/moveeeax/r53-dangling-dns/internal/core"
)

// Clients bundles the read-only AWS clients the scanner needs.
type Clients struct {
	Route53    *route53.Client
	ELBv2      *elbv2.Client
	ELB        *elb.Client
	CloudFront *cloudfront.Client
	S3         *s3.Client
	EC2        *ec2.Client
}

// NewClients builds every client from a shared aws.Config.
func NewClients(cfg aws.Config) *Clients {
	return &Clients{
		Route53:    route53.NewFromConfig(cfg),
		ELBv2:      elbv2.NewFromConfig(cfg),
		ELB:        elb.NewFromConfig(cfg),
		CloudFront: cloudfront.NewFromConfig(cfg),
		S3:         s3.NewFromConfig(cfg),
		EC2:        ec2.NewFromConfig(cfg),
	}
}

// ListRecords walks hosted zones and flattens every A/AAAA/CNAME record set to
// one core.Record per target value. When zoneFilter is non-empty only zones
// whose name equals it (with or without a trailing dot) are scanned.
func (c *Clients) ListRecords(ctx context.Context, zoneFilter string) ([]core.Record, error) {
	var records []core.Record
	zp := route53.NewListHostedZonesPaginator(c.Route53, &route53.ListHostedZonesInput{})
	for zp.HasMorePages() {
		page, err := zp.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list hosted zones: %w", err)
		}
		for _, z := range page.HostedZones {
			zoneName := aws.ToString(z.Name)
			if zoneFilter != "" && !zoneNameMatches(zoneName, zoneFilter) {
				continue
			}
			rp := route53.NewListResourceRecordSetsPaginator(c.Route53,
				&route53.ListResourceRecordSetsInput{HostedZoneId: z.Id})
			for rp.HasMorePages() {
				rr, err := rp.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list records for %s: %w", zoneName, err)
				}
				for i := range rr.ResourceRecordSets {
					records = append(records, flatten(zoneName, rr.ResourceRecordSets[i])...)
				}
			}
		}
	}
	return records, nil
}

// flatten turns one ResourceRecordSet into zero or more core.Records, one per
// target value. ALIAS records contribute a single record from AliasTarget.
func flatten(zone string, rs route53types.ResourceRecordSet) []core.Record {
	rtype := string(rs.Type)
	if rtype != "A" && rtype != "AAAA" && rtype != "CNAME" {
		return nil
	}
	name := aws.ToString(rs.Name)
	if rs.AliasTarget != nil {
		return []core.Record{{
			Zone: zone, Name: name, Type: rtype, IsAlias: true,
			Target: aws.ToString(rs.AliasTarget.DNSName),
		}}
	}
	out := make([]core.Record, 0, len(rs.ResourceRecords))
	for _, v := range rs.ResourceRecords {
		out = append(out, core.Record{Zone: zone, Name: name, Type: rtype, Target: aws.ToString(v.Value)})
	}
	return out
}

func zoneNameMatches(zoneName, filter string) bool {
	z := strings.TrimSuffix(strings.ToLower(zoneName), ".")
	f := strings.TrimSuffix(strings.ToLower(filter), ".")
	return z == f
}

// CollectInventory gathers the set of live AWS resources referenced by DNS.
// Any collector error is returned rather than swallowed: a partial inventory
// would produce false "dangling" findings on live infrastructure.
func (c *Clients) CollectInventory(ctx context.Context) (core.Inventory, error) {
	inv := core.NewInventory()

	// ELBv2 (ALB/NLB).
	lp := elbv2.NewDescribeLoadBalancersPaginator(c.ELBv2, &elbv2.DescribeLoadBalancersInput{})
	for lp.HasMorePages() {
		page, err := lp.NextPage(ctx)
		if err != nil {
			return inv, fmt.Errorf("describe load balancers (v2): %w", err)
		}
		for _, lb := range page.LoadBalancers {
			if dn := aws.ToString(lb.DNSName); dn != "" {
				inv.ELBDNSNames[strings.ToLower(dn)] = true
			}
		}
	}

	// Classic ELB.
	cp := elb.NewDescribeLoadBalancersPaginator(c.ELB, &elb.DescribeLoadBalancersInput{})
	for cp.HasMorePages() {
		page, err := cp.NextPage(ctx)
		if err != nil {
			return inv, fmt.Errorf("describe load balancers (classic): %w", err)
		}
		for _, lb := range page.LoadBalancerDescriptions {
			if dn := aws.ToString(lb.DNSName); dn != "" {
				inv.ELBDNSNames[strings.ToLower(dn)] = true
			}
		}
	}

	// CloudFront distributions (marker pagination).
	var marker *string
	for {
		out, err := c.CloudFront.ListDistributions(ctx, &cloudfront.ListDistributionsInput{Marker: marker})
		if err != nil {
			return inv, fmt.Errorf("list cloudfront distributions: %w", err)
		}
		if out.DistributionList != nil {
			for _, d := range out.DistributionList.Items {
				if dn := aws.ToString(d.DomainName); dn != "" {
					inv.CloudFrontDomains[strings.ToLower(dn)] = true
				}
			}
			if aws.ToBool(out.DistributionList.IsTruncated) {
				marker = out.DistributionList.NextMarker
				continue
			}
		}
		break
	}

	// S3 buckets.
	buckets, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return inv, fmt.Errorf("list s3 buckets: %w", err)
	}
	for _, b := range buckets.Buckets {
		if n := aws.ToString(b.Name); n != "" {
			inv.S3Buckets[n] = true
		}
	}

	// Elastic IPs.
	addrs, err := c.EC2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return inv, fmt.Errorf("describe addresses: %w", err)
	}
	for _, a := range addrs.Addresses {
		if ip := aws.ToString(a.PublicIp); ip != "" {
			inv.PublicIPs[ip] = true
		}
	}

	// Instance public IPs.
	ip := ec2.NewDescribeInstancesPaginator(c.EC2, &ec2.DescribeInstancesInput{})
	for ip.HasMorePages() {
		page, err := ip.NextPage(ctx)
		if err != nil {
			return inv, fmt.Errorf("describe instances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, in := range r.Instances {
				if v := aws.ToString(in.PublicIpAddress); v != "" {
					inv.PublicIPs[v] = true
				}
			}
		}
	}

	return inv, nil
}
