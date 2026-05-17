package checker

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
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

func lookupCAAHierarchy(ctx context.Context, _ *net.Resolver, host string) (string, []CAARecord) {
	trimmed := strings.Trim(strings.TrimSpace(host), ".")
	for current := trimmed; current != ""; current = parentDomain(current) {
		caa, err := lookupCAA(ctx, current)
		if err != nil || len(caa) == 0 {
			continue
		}
		return current, caa
	}
	return "", nil
}

func lookupCAA(ctx context.Context, host string) ([]CAARecord, error) {
	var lastErr error
	for _, server := range dnsServers() {
		records, err := queryCAAServer(ctx, server, host)
		if err == nil {
			return records, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no DNS servers configured")
}

func dnsServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fallbackDNSServers()
	}
	servers := make([]string, 0, 3)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		host := strings.Trim(fields[1], "[]")
		if net.ParseIP(host) == nil {
			continue
		}
		servers = append(servers, net.JoinHostPort(host, "53"))
		if len(servers) == 3 {
			break
		}
	}
	if len(servers) == 0 {
		return fallbackDNSServers()
	}
	return servers
}

func fallbackDNSServers() []string {
	return []string{"1.1.1.1:53", "8.8.8.8:53"}
}

func queryCAAServer(ctx context.Context, server, host string) ([]CAARecord, error) {
	queryID := randomQueryID()
	query, err := buildCAAQuery(queryID, host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseCAAResponse(buf[:n], queryID)
}

func randomQueryID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint16(b[:])
	}
	return uint16(time.Now().UnixNano())
}

func buildCAAQuery(id uint16, host string) ([]byte, error) {
	name, err := encodeDNSName(host)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, 12+len(name)+4)
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, name...)
	msg = binary.BigEndian.AppendUint16(msg, 257)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	return msg, nil
}

func encodeDNSName(host string) ([]byte, error) {
	trimmed := strings.Trim(strings.TrimSpace(host), ".")
	if trimmed == "" {
		return nil, fmt.Errorf("empty DNS name")
	}
	parts := strings.Split(trimmed, ".")
	out := make([]byte, 0, len(trimmed)+2)
	for _, part := range parts {
		if part == "" || len(part) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q", part)
		}
		out = append(out, byte(len(part)))
		out = append(out, part...)
	}
	out = append(out, 0)
	return out, nil
}

func parseCAAResponse(msg []byte, expectedID uint16) ([]CAARecord, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("short DNS response")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != expectedID {
		return nil, fmt.Errorf("DNS response ID mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if rcode := flags & 0x000f; rcode != 0 && rcode != 3 {
		return nil, fmt.Errorf("DNS response code %d", rcode)
	}

	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	offset := 12
	var err error
	for i := 0; i < qdCount; i++ {
		offset, err = skipDNSName(msg, offset)
		if err != nil {
			return nil, err
		}
		if offset+4 > len(msg) {
			return nil, fmt.Errorf("short DNS question")
		}
		offset += 4
	}

	records := make([]CAARecord, 0)
	for i := 0; i < anCount; i++ {
		offset, err = skipDNSName(msg, offset)
		if err != nil {
			return nil, err
		}
		if offset+10 > len(msg) {
			return nil, fmt.Errorf("short DNS answer")
		}
		rrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		rdLength := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10
		if offset+rdLength > len(msg) {
			return nil, fmt.Errorf("short DNS rdata")
		}
		if rrType == 257 && rrClass == 1 {
			record, ok := parseCAARData(msg[offset : offset+rdLength])
			if ok {
				records = append(records, record)
			}
		}
		offset += rdLength
	}
	return records, nil
}

func skipDNSName(msg []byte, offset int) (int, error) {
	for {
		if offset >= len(msg) {
			return 0, fmt.Errorf("short DNS name")
		}
		length := int(msg[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(msg) {
				return 0, fmt.Errorf("short DNS compression pointer")
			}
			return offset + 2, nil
		}
		if length&0xc0 != 0 {
			return 0, fmt.Errorf("unsupported DNS label")
		}
		offset++
		if length == 0 {
			return offset, nil
		}
		offset += length
	}
}

func parseCAARData(data []byte) (CAARecord, bool) {
	if len(data) < 2 {
		return CAARecord{}, false
	}
	tagLen := int(data[1])
	if tagLen == 0 || 2+tagLen > len(data) {
		return CAARecord{}, false
	}
	return CAARecord{
		Flag:  data[0],
		Tag:   string(data[2 : 2+tagLen]),
		Value: string(data[2+tagLen:]),
	}, true
}

func parentDomain(host string) string {
	idx := strings.IndexByte(host, '.')
	if idx < 0 || idx+1 >= len(host) {
		return ""
	}
	return host[idx+1:]
}
