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
	resolver = "8.8.8.8"
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

func getIP(host string, qtype uint16) []net.IP {
	var ips []net.IP
	rrset, _, err := queryRRset(host, qtype, resolver, false)
	if err != nil {
		return ips
	}
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

func extractRR(rrset []dns.RR, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrset {
		if rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

func query(q string, qtype uint16, server string, sec bool) (*dns.Msg, time.Duration, error) {
	c := new(dns.Client)
	m := prepMsg()
	m.CheckingDisabled = true
	if sec {
		m.CheckingDisabled = false
		m.SetEdns0(4096, true)
	}
	m.Question[0] = dns.Question{dns.Fqdn(q), qtype, dns.ClassINET}
	in, rtt, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, 0, err
	}
	return in, rtt, nil
}

func queryRRset(q string, qtype uint16, server string, sec bool) ([]dns.RR, time.Duration, error) {
	res, rtt, err := query(q, qtype, server, sec)
	if err != nil {
		return []dns.RR{}, 0, err
	}
	rrset := extractRR(res.Answer, qtype)
	if len(rrset) == 0 {
		return []dns.RR{}, 0, fmt.Errorf("no rr for %#v", qtype)
	}
	return rrset, rtt, nil
}

func validateRR(keys []dns.RR, rrset []dns.RR) (bool, KeyInfo, error) {
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
	for _, k := range keys {
		key := k.(*dns.DNSKEY)
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
	rrset, _, err := queryRRset(domain, dns.TypeNS, resolver, false)
	if err != nil {
		return []NSInfo{}, nil
	}
	var nsinfos []NSInfo
	for _, rr := range rrset {
		ns := rr.(*dns.NS).Ns
		nsinfo := NSInfo{}
		ips := []net.IP{}
		nsinfo.Name = ns
		ips = append(ips, getIP(ns, dns.TypeA)...)
		ips = append(ips, getIP(ns, dns.TypeAAAA)...)
		nsinfo.IP = ips
		nsinfos = append(nsinfos, nsinfo)
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
				soa, rtt, err := queryRRset(domain, dns.TypeSOA, ip.String(), false)
				if err != nil {
					output = output + fmt.Sprintf("%s\t%v\t", "error", "error")
				} else {
					output = output + fmt.Sprintf("%s\t%v\t", rtt.String(), int64(soa[0].(*dns.SOA).Serial))
				}
				keys, _, err := queryRRset(domain, dns.TypeDNSKEY, ip.String(), true)
				if err != nil {
				}
				res, _, err := query(domain, dns.TypeNS, ip.String(), true)
				if err != nil {
				}
				valid, keyinfo, err := validateRR(keys, res.Answer)
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
