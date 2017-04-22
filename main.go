package main

import (
	"fmt"
	"net"
	"sync"
	"text/tabwriter"
	"time"

	"os"

	"github.com/42wim/ipisp"
	"github.com/dustin/go-humanize"
	"github.com/miekg/dns"
)

var (
	resolver = "8.8.8.8:53"
	wc       chan string
	done     chan struct{}
)

type NSInfo struct {
	Name string
	IP   []net.IP
}

type IPInfo struct {
	Loc string
	ASN ipisp.ASN
	ISP string
}

type KeyInfo struct {
	Start int64
	End   int64
}

func ipinfo(ip net.IP) (IPInfo, error) {
	client, _ := ipisp.NewDNSClient()
	resp, err := client.LookupIP(net.ParseIP(ip.String()))
	if err != nil {
		return IPInfo{}, err
	}
	return IPInfo{resp.Country, resp.ASN, resp.Name.Raw}, nil
}

func typeSOA(q string, server string) (time.Duration, *dns.SOA, error) {
	c := new(dns.Client)
	m := prepMsg()
	m.Question[0] = dns.Question{q + ".", dns.TypeSOA, dns.ClassINET}
	in, rtt, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return 0, new(dns.SOA), err
	}
	return rtt, in.Answer[0].(*dns.SOA), nil
}

func getIP(host string, qtype uint16) []net.IP {
	var ips []net.IP
	c := new(dns.Client)
	m := prepMsg()
	m.Question[0] = dns.Question{host, qtype, dns.ClassINET}
	in, _, err := c.Exchange(m, resolver)
	if err != nil {
		return ips
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

func typeA(host string) []net.IP {
	return getIP(host, dns.TypeA)
}

func typeAAAA(host string) []net.IP {
	return getIP(host, dns.TypeAAAA)
}

func typeDNSKEY(q string, server string) (bool, KeyInfo, error) {
	c := new(dns.Client)
	m := prepMsg()
	m.SetEdns0(4096, true)
	m.Question[0] = dns.Question{q + ".", dns.TypeDNSKEY, dns.ClassINET}
	in, _, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return false, KeyInfo{}, err
	}
	keys := []*dns.DNSKEY{}
	for _, a := range in.Answer {
		switch a.(type) {
		case *dns.DNSKEY:
			keys = append(keys, a.(*dns.DNSKEY))
		}
	}

	// ask dnssec
	m = prepMsg()
	m.SetEdns0(4096, true)
	m.Question[0] = dns.Question{q + ".", dns.TypeNS, dns.ClassINET}
	in, _, err = c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return false, KeyInfo{}, err
	}
	return validateRR(keys, in.Answer)
}

func validateRR(keys []*dns.DNSKEY, rrset []dns.RR) (bool, KeyInfo, error) {
	if len(rrset) == 0 {
		return false, KeyInfo{}, nil
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
					return true, KeyInfo{ti, te}, nil
				}
				return false, KeyInfo{ti, te}, nil
			}
		}
	}
	return false, KeyInfo{}, nil
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

func findNS(domain string) ([]NSInfo, error) {
	c := new(dns.Client)
	m := prepMsg()
	m.Question[0] = dns.Question{domain, dns.TypeNS, dns.ClassINET}
	var ips []net.IP
	var nsinfos []NSInfo
	in, _, err := c.Exchange(m, resolver)
	if err != nil {
		return nsinfos, err
	}
	for _, a := range in.Answer {
		nsinfo := NSInfo{}
		nsinfo.Name = a.(*dns.NS).Ns
		ips = append(ips, typeA(a.(*dns.NS).Ns)...)
		ips = append(ips, typeAAAA(a.(*dns.NS).Ns)...)
		nsinfo.IP = ips
		nsinfos = append(nsinfos, nsinfo)
		ips = []net.IP{}
	}
	return nsinfos, nil
}

func prepMsg() *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	return m
}

func outputter() {
	const padding = 1
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.Debug)
	for input := range wc {
		fmt.Fprintf(w, input)
	}
	w.Flush()
	done <- struct{}{}
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("please enter a domain. (e.g. google.com)")
		return
	}
	domain := os.Args[1]
	nsinfos, err := findNS(dns.Fqdn(domain))
	if len(nsinfos) == 0 {
		fmt.Println("no nameservers found for", domain)
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	wc = make(chan string)
	done = make(chan struct{})
	var wg sync.WaitGroup
	go outputter()

	wc <- fmt.Sprintf("NS\tIP\tLOC\tASN\tISP\trtt\tSerial\tDNSSEC\tValidFrom\tValidUntil\n")
	for _, nsinfo := range nsinfos {
		wg.Add(1)
		go func(nsinfo NSInfo) {
			output := fmt.Sprintf("%s\t", nsinfo.Name)
			i := 0
			for _, ip := range nsinfo.IP {
				info, _ := ipinfo(ip)
				if i > 0 {
					output = output + fmt.Sprintf("\t%s\t", ip.String())
				} else {
					output = output + fmt.Sprintf("%s\t", ip.String())
				}
				output = output + fmt.Sprintf("%v\tASN %#v\t%v\t", info.Loc, info.ASN, fmt.Sprintf("%.40s", info.ISP))
				rtt, soa, err := typeSOA(domain, ip.String())
				if err != nil {
					output = output + fmt.Sprintf("%s\t%v\t", "error", "error")
				} else {
					output = output + fmt.Sprintf("%s\t%v\t", rtt.String(), int64(soa.Serial))
				}
				valid, keyinfo, err := typeDNSKEY(domain, ip.String())
				if valid {
					output = output + fmt.Sprintf("%v\t%s\t%s", "valid", humanize.Time(time.Unix(keyinfo.Start, 0)), humanize.Time(time.Unix(keyinfo.End, 0)))
				} else {
					if err != nil {
						output = output + fmt.Sprintf("%v\t%s\t%s", "error", "", "")
					} else {
						if keyinfo.Start == 0 {
							output = output + fmt.Sprintf("%v\t%s\t%s", "disabled", "", "")
						} else {
							output = output + fmt.Sprintf("%v\t%s\t%s", "invalid", "", "")
						}
					}
				}
				output = output + fmt.Sprintln()
				i++
			}
			wc <- output
			wg.Done()
		}(nsinfo)
	}
	wg.Wait()
	close(wc)
	<-done
}
