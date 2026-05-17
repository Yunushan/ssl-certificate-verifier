package checker

import (
	"context"
	"net"
	"strings"
	"time"
)

func checkDNS(ctx context.Context, target Target, opt Options, result *Result) {
	result.DNS.Attempted = true
	result.DNS.Hostname = target.Host

	timeout := normalizeTimeout(opt.Timeout)
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resolver := net.DefaultResolver
	if target.IsIP {
		ptr, err := resolver.LookupAddr(dnsCtx, target.Host)
		if err != nil {
			result.DNS.Error = shortError(err)
			result.Warnings = append(result.Warnings, "dns: reverse lookup failed: "+shortError(err))
			return
		}
		result.DNS.PTR = append([]string(nil), ptr...)
		return
	}

	if cname, err := resolver.LookupCNAME(dnsCtx, target.Host); err == nil {
		result.DNS.CNAME = cname
	}

	if addrs, err := resolver.LookupIP(dnsCtx, "ip4", target.Host); err == nil {
		for _, addr := range addrs {
			result.DNS.A = append(result.DNS.A, addr.String())
		}
	} else {
		result.Warnings = append(result.Warnings, "dns: A lookup failed: "+shortError(err))
	}

	if addrs, err := resolver.LookupIP(dnsCtx, "ip6", target.Host); err == nil {
		for _, addr := range addrs {
			result.DNS.AAAA = append(result.DNS.AAAA, addr.String())
		}
	}

	result.DNS.CAAHost, result.DNS.CAA = lookupCAAHierarchy(dnsCtx, resolver, target.Host)
}

func lookupCAAHierarchy(ctx context.Context, resolver *net.Resolver, host string) (string, []CAARecord) {
	trimmed := strings.Trim(strings.TrimSpace(host), ".")
	for current := trimmed; current != ""; current = parentDomain(current) {
		caa, err := resolver.LookupCAA(ctx, current)
		if err != nil || len(caa) == 0 {
			continue
		}
		records := make([]CAARecord, 0, len(caa))
		for _, record := range caa {
			records = append(records, CAARecord{
				Flag:  record.Flag,
				Tag:   record.Tag,
				Value: record.Value,
			})
		}
		return current, records
	}
	return "", nil
}

func parentDomain(host string) string {
	idx := strings.IndexByte(host, '.')
	if idx < 0 || idx+1 >= len(host) {
		return ""
	}
	return host[idx+1:]
}
