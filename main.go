package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"text/tabwriter"
	"time"

	"os"

	"github.com/42wim/ipisp"
	"github.com/Sirupsen/logrus"
	"github.com/briandowns/spinner"
	"github.com/dustin/go-humanize"
	"github.com/miekg/dns"
)

var (
	resolver            = "8.8.8.8"
	wc                  chan NSInfo
	done                chan struct{}
	flagScan, flagDebug *bool
	flagQPS             *int
	log                 = logrus.New()
)

type NSInfo struct {
	Name   string
	Rtt    time.Duration
	Serial int64
	IPInfo
	DNSSECInfo
}

type NSData struct {
	Name string
	Info []NSInfo
	IP   []net.IP
}

type IPInfo struct {
	IP  net.IP
	Loc string
	ASN ipisp.ASN
	ISP string
}

type DNSSECInfo struct {
	Valid      bool
	ChainValid bool
	Disabled   bool
	KeyInfo
}

type KeyInfo struct {
	Start int64
	End   int64
}

type DomainStat struct {
	Domain string
	NS     []NSInfo
}

type Response struct {
	RR  []dns.RR
	IP  net.IP
	Rtt time.Duration
}

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
	if in.Rcode != 0 {
		return in, rtt, fmt.Errorf("failure: %s", dns.RcodeToString[in.Rcode])
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

func outputter() {
	const padding = 1
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.Debug)
	fmt.Fprintf(w, "NS\tIP\tLOC\tASN\tISP\trtt\tSerial\tDNSSEC\tValidFrom\tValidUntil\n")
	m := make(map[string][]NSInfo)
	for input := range wc {
		m[input.Name] = append(m[input.Name], input)
	}
	for _, info := range m {
		i := 0
		var failed bool
		for _, ns := range info {
			if ns.Rtt == 0 {
				failed = true
			}
			if failed {
				fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.Name, ns.IPInfo.IP.String(), ns.Loc, ns.ASN, ns.ISP, "error", "error", "error")
				fmt.Fprintln(w)
				break
			}
			if i == 0 {
				fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.Name, ns.IPInfo.IP.String(), ns.Loc, ns.ASN, fmt.Sprintf("%.40s", ns.ISP), ns.Rtt, ns.Serial)
			} else {
				fmt.Fprintf(w, "\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.IPInfo.IP.String(), ns.Loc, ns.ASN, fmt.Sprintf("%.40s", ns.ISP), ns.Rtt, ns.Serial)
			}
			if ns.Valid && ns.ChainValid {
				fmt.Fprintf(w, "%v\t%s\t%s", "valid", humanize.Time(time.Unix(ns.KeyInfo.Start, 0)), humanize.Time(time.Unix(ns.KeyInfo.End, 0)))
			} else {
				if ns.DNSSECInfo.Disabled {
					fmt.Fprintf(w, "%v\t%s\t%s", "disabled", "", "")
				} else {
					fmt.Fprintf(w, "%v\t%s\t%s", "invalid", humanize.Time(time.Unix(ns.KeyInfo.Start, 0)), humanize.Time(time.Unix(ns.KeyInfo.End, 0)))
				}
			}
			i++
			fmt.Fprintln(w)
		}
	}
	w.Flush()
	done <- struct{}{}
}

func writeStats() {

}

func main() {
	flagDebug = flag.Bool("debug", false, "enable debug")
	flagScan = flag.Bool("scan", false, "scan domain for common records")
	flagQPS = flag.Int("qps", 10, "Queries per seconds (per nameserver)")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Usage:")
		fmt.Println("\tdt [FLAGS] domain")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("\tdt icann.org")
		fmt.Println("\tdt -debug ripe.net")
		fmt.Println("\tdt -debug -scan yourdomain.com")
		fmt.Println()
		fmt.Println("Flags:")
		flag.PrintDefaults()
		return
	}

	if *flagDebug {
		log.Level = logrus.DebugLevel
	}

	domain := flag.Arg(0)
	nsdatas, err := findNS(dns.Fqdn(domain))
	if len(nsdatas) == 0 {
		fmt.Println("no nameservers found for", domain)
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}

	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if !*flagDebug {
		s.Start()
	}

	// check dnssec
	chainValid, chainErr := validateChain(dns.Fqdn(domain))

	wc = make(chan NSInfo)
	done = make(chan struct{})
	var wg sync.WaitGroup
	go outputter()

	// for now disable debuglevel (because of multiple goroutines output)
	if *flagDebug {
		log.Level = logrus.InfoLevel
	}

	for _, nsdata := range nsdatas {
		wg.Add(1)
		go func(nsinfos []NSInfo) {
			for _, nsinfo := range nsinfos {
				var newnsinfo NSInfo
				ip := nsinfo.IP
				info, _ := ipinfo(ip)
				newnsinfo.IPInfo = info
				newnsinfo.Name = nsinfo.Name

				soa, rtt, err := queryRRset(domain, dns.TypeSOA, ip.String(), false)
				if err == nil {
					newnsinfo.Rtt = rtt
					newnsinfo.Serial = int64(soa[0].(*dns.SOA).Serial)
				}

				keys, _, _ := queryRRset(domain, dns.TypeDNSKEY, ip.String(), true)
				res, _, err := query(domain, dns.TypeNS, ip.String(), true)
				if err == nil {
					valid, keyinfo, _ := validateRRSIG(keys, res.Answer)
					newnsinfo.DNSSECInfo = DNSSECInfo{Valid: valid, KeyInfo: keyinfo, ChainValid: chainValid}
					if keyinfo.Start == 0 && len(keys) == 0 {
						newnsinfo.Disabled = true
					}
				}
				wc <- newnsinfo
			}
			wg.Done()
		}(nsdata.Info)
	}

	wg.Wait()
	close(wc)
	s.Stop()
	<-done

	if chainErr != nil {
		fmt.Printf("DNSSEC: %s\n", chainErr)
	}

	// enable debug again if needed
	if *flagDebug {
		log.Level = logrus.DebugLevel
	}

	g := &Glue{NS: nsdatas}
	glue, missed, err := g.CheckParent(domain)
	if !glue {
		// TODO print more information
		fmt.Printf("GLUE: no glue records found for %s in NS of parent %s\n", missed, dns.Fqdn(getParentDomain(domain)))
	}
	glue, missed, err = g.CheckSelf(domain)
	if !glue {
		// TODO print more information
		fmt.Printf("GLUE: no glue records found for %s in NS of %s\n", missed, dns.Fqdn(domain))
	}

	if *flagScan {
		domainscan(domain)
	}
}

func getParentDomain(domain string) string {
	i, end := dns.NextLabel(domain, 0)
	if !end {
		return domain[i:]
	}
	return "."
}
