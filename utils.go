package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ammario/ipisp"
	"github.com/miekg/dns"
)

func ipinfo(ip net.IP) (IPInfo, error) {
	client, _ := ipisp.NewDNSClient()
	resp, err := client.LookupIP(net.ParseIP(ip.String()))
	if err != nil {
		return IPInfo{}, err
	}
	return IPInfo{ip, resp.Country, resp.ASN, resp.Name.Raw}, nil
}

func getIP(host string, qtype uint16, servers ...string) []net.IP {
	var ips []net.IP
	for _, server := range servers {
		rrset, _, err := queryRRset(host, qtype, server, false)
		if err != nil {
			continue
		}
		return extractIP(rrset)
	}
	return ips
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

func query(q string, qtype uint16, server string, sec bool) (Response, error) {
	c := new(dns.Client)
	m := prepMsg()
	m.CheckingDisabled = true
	m.RecursionDesired = true
	if sec {
		m.CheckingDisabled = false
		m.SetEdns0(4096, true)
	}
	var resp Response
	log.Debugf("Asking %s about %s (%s)", server, q, dns.TypeToString[qtype])
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(q),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
	in, rtt, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return resp, err
	}
	if in.Rcode != 0 {
		resp.Rtt = rtt
		return resp, fmt.Errorf("failure: %s", dns.RcodeToString[in.Rcode])
	}
	return Response{Msg: in, Server: server, Rtt: rtt}, nil
}

func queryRRset(q string, qtype uint16, server string, sec bool) ([]dns.RR, time.Duration, error) {
	res, err := query(q, qtype, server, sec)
	if err != nil {
		return []dns.RR{}, res.Rtt, err
	}
	rrset := extractRR(res.Msg.Answer, qtype)
	if len(rrset) == 0 {
		return []dns.RR{}, res.Rtt, fmt.Errorf("no rr for %#v", qtype)
	}
	return rrset, res.Rtt, nil
}

func findNS(domain string) ([]NSData, error) {
	if nsdatas, ok := nsdataCache[domain]; ok {
		return nsdatas, nil
	}
	rrset, _, err := queryRRset(domain, dns.TypeNS, resolver, false)
	if err != nil {
		return []NSData{}, err
	}
	var nsdatas []NSData
	for _, rr := range rrset {
		var ips []net.IP
		nsdata := NSData{}
		ns := rr.(*dns.NS).Ns
		nsdata.Name = ns
		ips = append(ips, getIP(ns, dns.TypeA, resolver)...)
		ips = append(ips, getIP(ns, dns.TypeAAAA, resolver)...)
		var nsinfos []NSInfo
		for _, ip := range ips {
			nsinfos = append(nsinfos, NSInfo{IPInfo: IPInfo{IP: ip}, Name: ns})
		}
		nsdata.IP = ips
		nsdata.Info = nsinfos
		nsdatas = append(nsdatas, nsdata)
	}
	if len(nsdatas) == 0 {
		return nsdatas, fmt.Errorf("no NS found")
	}
	nsdataCache[domain] = nsdatas
	return nsdatas, nil
}

func prepMsg() *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	return m
}

func getParentDomain(domain string) string {
	i, end := dns.NextLabel(domain, 0)
	if !end {
		return domain[i:]
	}
	return "."
}

func isRFC1918(ip net.IP) bool {
	ten := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
	oneNineTwo := net.IPNet{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)}
	oneSevenTwo := net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}
	return ten.Contains(ip) || oneNineTwo.Contains(ip) || oneSevenTwo.Contains(ip)
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

func scanerror(r *Report, check, ns, ip, domain string, results []dns.RR, err error) bool {
	fail := false
	if err != nil {
		if !strings.Contains(err.Error(), "NXDOMAIN") && !strings.Contains(err.Error(), "no rr for") {
			r.Result = append(r.Result, ReportResult{Result: fmt.Sprintf("ERR : %s failed on %s (%s): %s", check, ns, ip, err)})
		}
		fail = true
	}
	if len(results) == 0 && err == nil {
		//		r.Result = append(r.Result, ReportResult{Result: fmt.Sprintf("ERR : %s failed on %s (%s): %s", check, ns, ip, "no records found")})
		fail = true
	}
	return fail
}

func removeWild(wild []string, rrset []dns.RR) []dns.RR {
	if len(wild) == 0 {
		return rrset
	}
	newset := []dns.RR{}
	for _, rr := range rrset {
		match := false
		switch rr := rr.(type) {
		case *dns.A:
			for _, ip := range wild {
				if rr.A.String() == ip {
					match = true
				}
			}
		case *dns.AAAA:
			for _, ip := range wild {
				if rr.AAAA.String() == ip {
					match = true
				}
			}
		}
		if !match {
			newset = append(newset, rr)
		}
	}
	return newset
}

func removeIPv6(nsdatas []NSData) []NSData {
	var newdatas []NSData
	for _, nsdata := range nsdatas {
		var ips []net.IP
		var infos []NSInfo
		for _, ip := range nsdata.IP {
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
		nsdata.IP = ips

		for _, info := range nsdata.Info {
			if info.IP.To4() != nil {
				infos = append(infos, info)
			}
		}
		nsdata.Info = infos

		newdatas = append(newdatas, nsdata)
	}
	return newdatas
}
