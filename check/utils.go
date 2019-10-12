package check

import (
	"net"

	"github.com/42wim/dt/structs"
	"github.com/ammario/ipisp"
	"github.com/miekg/dns"
)

func getParentDomain(domain string) string {
	i, end := dns.NextLabel(domain, 0)
	if !end {
		return domain[i:]
	}
	return "."
}

func extractRR(rrset []dns.RR, qtypes ...uint16) []dns.RR {
	var out []dns.RR
	m := make(map[uint16]bool)
	for _, qtype := range qtypes {
		m[qtype] = true
	}
	for _, rr := range rrset {
		if _, ok := m[rr.Header().Rrtype]; ok {
			out = append(out, rr)
		}
	}
	return out
}

func extractRRMsg(msg *dns.Msg, qtypes ...uint16) []dns.RR {
	if msg != nil {
		return extractRR(msg.Answer, qtypes...)
	}
	return []dns.RR{}
}

func extractIP(rrset []dns.RR) []net.IP {
	var ips []net.IP
	for _, rr := range rrset {
		switch rr := rr.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			ips = append(ips, rr.AAAA)
		}
	}
	return ips
}

func isRFC1918(ip net.IP) bool {
	ten := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
	oneNineTwo := net.IPNet{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)}
	oneSevenTwo := net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}
	return ten.Contains(ip) || oneNineTwo.Contains(ip) || oneSevenTwo.Contains(ip)
}

func ipinfo(ip net.IP) (structs.IPInfo, error) {
	client, _ := ipisp.NewDNSClient()
	resp, err := client.LookupIP(net.ParseIP(ip.String()))
	if err != nil {
		return structs.IPInfo{}, err
	}
	return structs.IPInfo{
		IP:  ip,
		Loc: resp.Country,
		ASN: resp.ASN,
		ISP: resp.Name.Raw,
	}, nil
}

func isSameSubnet(ips ...net.IP) bool {
	// ipv4 only for now
	var ipnets []net.IPNet
	ipv4 := 0
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4++
			ipnets = append(ipnets, net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)})
		}
	}
	count := 0
	for _, ipnet := range ipnets {
		for _, ip := range ips {
			if ipnet.Contains(ip) {
				count++
			}
		}
	}
	return count == ipv4*len(ipnets)
}
