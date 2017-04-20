package main

import (
	"fmt"
	"net"
	"time"

	"os"

	"github.com/42wim/ipisp"
	"github.com/dustin/go-humanize"
	"github.com/miekg/dns"
	"text/tabwriter"
)

var resolver = "8.8.8.8:53"

type NSInfo struct {
	Name string
	IP   []net.IP
}

func ipinfo(ip net.IP) (string, ipisp.ASN, string) {
	client, _ := ipisp.NewDNSClient()
	resp, err := client.LookupIP(net.ParseIP(ip.String()))
	if err != nil {
		fmt.Println(err)
	}
	return resp.Country, resp.ASN, resp.Name.Raw
}

func typeSOA(q string, server string) (time.Duration, *dns.SOA) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{q + ".", dns.TypeSOA, dns.ClassINET}
	in, rtt, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		fmt.Println(err)
	}
	return rtt, in.Answer[0].(*dns.SOA)
}

func typeA(q string) []net.IP {
	var ips []net.IP
	c := new(dns.Client)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{q, dns.TypeA, dns.ClassINET}
	in, rtt, err := c.Exchange(m, resolver)
	if err != nil {
		fmt.Println(err, rtt)
	}
	for _, a := range in.Answer {
		switch a.(type) {
		case *dns.A:
			ips = append(ips, a.(*dns.A).A)
		case *dns.AAAA:
			ips = append(ips, a.(*dns.AAAA).AAAA)
		}
	}
	return ips
}

func typeAAAA(q string) []net.IP {
	var ips []net.IP
	c := new(dns.Client)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{q, dns.TypeAAAA, dns.ClassINET}
	in, rtt, err := c.Exchange(m, resolver)
	if err != nil {
		fmt.Println(err, rtt)
	}
	for _, a := range in.Answer {
		switch a.(type) {
		case *dns.A:
			ips = append(ips, a.(*dns.A).A)
		case *dns.AAAA:
			ips = append(ips, a.(*dns.AAAA).AAAA)
		}
	}
	return ips
}

func typeDNSKEY(q string, server string) (bool, int64, int64) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.SetEdns0(4096, true)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{q + ".", dns.TypeDNSKEY, dns.ClassINET}
	in, rtt, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		fmt.Println(err, rtt)
	}
	keys := []*dns.DNSKEY{}
	sigs := []*dns.RRSIG{}
	for _, a := range in.Answer {
		switch a.(type) {
		case *dns.DNSKEY:
			keys = append(keys, a.(*dns.DNSKEY))
		case *dns.RRSIG:
			sigs = append(sigs, a.(*dns.RRSIG))
		}
	}

	m = new(dns.Msg)
	m.Id = dns.Id()
	m.SetEdns0(4096, true)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{q + ".", dns.TypeNS, dns.ClassINET}
	in, rtt, err = c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		fmt.Println(err)
	}
	return validateRR(keys, in.Answer)
}

func validateRR(keys []*dns.DNSKEY, rrset []dns.RR) (bool, int64, int64) {
	if len(rrset) == 0 {
		return false, 0, 0
	}
	var sig *dns.RRSIG
	var cleanset []dns.RR
	for _, v := range rrset {
		_, ok := v.(*dns.RRSIG)
		if ok {
			sig = v.(*dns.RRSIG)
		} else {
			cleanset = append(cleanset, v)
		}
	}
	for _, key := range keys {
		// zone signing key
		if key.Flags == 256 {
			err := sig.Verify(key, cleanset)
			if err == nil {
				ti, te := explicitValid(sig)
				if sig.ValidityPeriod(time.Now()) {
					return true, ti, te
				}
				return false, ti, te
			}
		}
	}
	return false, 0, 0
}

func explicitValid(rr *dns.RRSIG) (int64, int64) {
	t := time.Now()
	var utc int64
	var year68 = int64(1 << 31)
	if t.IsZero() {
		utc = time.Now().UTC().Unix()
	} else {
		utc = t.UTC().Unix()
	}
	modi := (int64(rr.Inception) - utc) / year68
	mode := (int64(rr.Expiration) - utc) / year68
	ti := int64(rr.Inception) + (modi * year68)
	te := int64(rr.Expiration) + (mode * year68)
	return ti, te
}

func findNS(domain string) []NSInfo {
	c := new(dns.Client)
	m := prepMsg()
	m.Question[0] = dns.Question{domain, dns.TypeNS, dns.ClassINET}
	in, _, err := c.Exchange(m, resolver)
	if err != nil {
		fmt.Println(err)
	}
	var ips []net.IP
	var nsinfos []NSInfo
	for _, a := range in.Answer {
		nsinfo := NSInfo{}
		nsinfo.Name = a.(*dns.NS).Ns
		ips = append(ips, typeA(a.(*dns.NS).Ns)...)
		ips = append(ips, typeAAAA(a.(*dns.NS).Ns)...)
		nsinfo.IP = ips
		nsinfos = append(nsinfos, nsinfo)
		ips = []net.IP{}
	}
	return nsinfos
}

func prepMsg() *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	return m
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("please enter a domain. (e.g. google.com)")
		return
	}
	nsinfos := findNS(dns.Fqdn(os.Args[1]))
	if len(nsinfos) == 0 {
		fmt.Println("no nameservers found for", os.Args[1])
		return
	}
	const padding = 1
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.Debug)
	fmt.Fprintf(w, "NS\tIP\tLOC\tASN\tISP\trtt\tSerial\tDNSSEC\tValidFrom\tValidUntil\n")
	for _, nsinfo := range nsinfos {
		fmt.Fprintf(w, "%s\t", nsinfo.Name)
		i := 0
		for _, ip := range nsinfo.IP {
			country, asn, isp := ipinfo(ip)
			if i > 0 {
				fmt.Fprintf(w, "\t%s\t", ip.String())
			} else {
				fmt.Fprintf(w, "%s\t", ip.String())
			}
			fmt.Fprintf(w, "%v\tASN %#v\t%v\t", country, asn, fmt.Sprintf("%.40s", isp))
			rtt, soa := typeSOA(os.Args[1], ip.String())
			valid, ti, te := typeDNSKEY(os.Args[1], ip.String())
			fmt.Fprintf(w, "%s\t%v\t", rtt.String(), int64(soa.Serial))
			if valid {
				fmt.Fprintf(w, "%v\t%s\t%s", valid, humanize.Time(time.Unix(ti, 0)), humanize.Time(time.Unix(te, 0)))
			} else {
				fmt.Fprintf(w, "%v\t%s\t%s", valid, "", "")
			}
			fmt.Fprintln(w)
			i++
		}
	}
	w.Flush()
	fmt.Println()
}
