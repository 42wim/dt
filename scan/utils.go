package scan

import (
	"fmt"
	"net"
	"time"

	"github.com/42wim/dt/structs"
	"github.com/ammario/ipisp"
	"github.com/miekg/dns"
)

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

func QueryClass(q string, qtype uint16, server string, sec bool, class uint16) (structs.Response, error) {
	c := new(dns.Client)
	m := prepMsg()

	m.CheckingDisabled = true
	m.RecursionDesired = true

	if sec {
		m.CheckingDisabled = false
		m.SetEdns0(4096, true)
	}

	var resp structs.Response

	log.Debugf("Asking %s about %s (%s)", server, q, dns.TypeToString[qtype])

	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(q),
		Qtype:  qtype,
		Qclass: class,
	}

	in, rtt, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return resp, err
	}

	if in.Rcode != 0 {
		resp.Rtt = rtt
		return resp, fmt.Errorf("failure: %s", dns.RcodeToString[in.Rcode])
	}

	return structs.Response{
		Msg:    in,
		Server: server,
		Rtt:    rtt,
	}, nil
}

func query(q string, qtype uint16, server string, sec bool) (structs.Response, error) {
	return QueryClass(q, qtype, server, sec, dns.ClassINET)
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

func (s *Scan) FindNS(domain string) ([]structs.NSData, error) {
	if nsdatas, ok := s.nsdataCache[domain]; ok {
		return nsdatas, nil
	}

	rrset, _, err := queryRRset(domain, dns.TypeNS, s.resolver, false)
	if err != nil {
		return []structs.NSData{}, err
	}

	var nsdatas []structs.NSData

	for _, rr := range rrset {
		var ips []net.IP

		nsdata := structs.NSData{}
		ns := rr.(*dns.NS).Ns

		nsdata.Name = ns
		ips = append(ips, getIP(ns, dns.TypeA, s.resolver)...)
		ips = append(ips, getIP(ns, dns.TypeAAAA, s.resolver)...)

		var nsinfos []structs.NSInfo

		for _, ip := range ips {
			nsinfos = append(nsinfos, structs.NSInfo{IPInfo: structs.IPInfo{IP: ip}, Name: ns})
		}

		nsdata.IP = ips
		nsdata.Info = nsinfos
		nsdatas = append(nsdatas, nsdata)
	}

	if len(nsdatas) == 0 {
		return nsdatas, fmt.Errorf("no NS found")
	}

	s.nsdataCache[domain] = nsdatas

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
