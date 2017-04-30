package main

import (
	"fmt"
	"net"
	"time"

	"github.com/42wim/ipisp"
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

func getIP(host string, qtype uint16, server string) []net.IP {
	var ips []net.IP
	rrset, _, err := queryRRset(host, qtype, server, false)
	if err != nil {
		return ips
	}
	return extractIP(rrset)
}

func extractIP(rrset []dns.RR) []net.IP {
	var ips []net.IP
	for _, rr := range rrset {
		switch rr.(type) {
		case *dns.A:
			ips = append(ips, rr.(*dns.A).A)
		case *dns.AAAA:
			ips = append(ips, rr.(*dns.AAAA).AAAA)
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

func query(q string, qtype uint16, server string, sec bool) (Response, error) {
	c := new(dns.Client)
	m := prepMsg()
	m.CheckingDisabled = true
	if sec {
		m.CheckingDisabled = false
		m.SetEdns0(4096, true)
	}
	var resp Response
	m.Question[0] = dns.Question{dns.Fqdn(q), qtype, dns.ClassINET}
	in, rtt, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return resp, err
	}
	if in.Rcode != 0 {
		return resp, fmt.Errorf("failure: %s", dns.RcodeToString[in.Rcode])
	}
	return Response{Msg: in, Server: server, Rtt: rtt}, nil
}

func queryRRset(q string, qtype uint16, server string, sec bool) ([]dns.RR, time.Duration, error) {
	res, err := query(q, qtype, server, sec)
	if err != nil {
		return []dns.RR{}, 0, err
	}
	rrset := extractRR(res.Msg.Answer, qtype)
	if len(rrset) == 0 {
		return []dns.RR{}, 0, fmt.Errorf("no rr for %#v", qtype)
	}
	return rrset, res.Rtt, nil
}

func findNS(domain string) ([]NSData, error) {
	rrset, _, err := queryRRset(domain, dns.TypeNS, resolver, false)
	if err != nil {
		return []NSData{}, nil
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
