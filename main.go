package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"text/tabwriter"
	"time"

	"os"

	"encoding/json"
	"github.com/42wim/ipisp"
	"github.com/Sirupsen/logrus"
	"github.com/briandowns/spinner"
	"github.com/dustin/go-humanize"
	"github.com/miekg/dns"
)

var (
	resolver                                    string
	wc                                          chan NSInfo
	done                                        chan struct{}
	flagScan, flagDebug, flagShowFail, flagJSON *bool
	flagQPS                                     *int
	log                                         = logrus.New()
	domainReport                                DomainReport
	IPv6Guess                                   bool
	nsdataCache                                 map[string][]NSData
)

type NSInfo struct {
	Name   string
	Rtt    time.Duration
	Serial int64
	IPInfo
	DNSSECInfo
	Msg *dns.Msg `json:"-"`
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
	Msg    *dns.Msg
	Server string
	Rtt    time.Duration
}

type Report struct {
	Type   string
	Result []ReportResult
}

type ReportResult struct {
	Result  string
	Status  bool
	Error   string
	Records []string
	Name    string
}

type DomainReport struct {
	Name      string
	NSInfo    []NSInfo
	Timestamp time.Time
	Report    []Report
	Scan      []ScanResponse
}

func outputter() {
	const padding = 1
	var w *tabwriter.Writer
	if *flagJSON {
		w = tabwriter.NewWriter(ioutil.Discard, 0, 0, padding, ' ', tabwriter.Debug)
	} else {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.Debug)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "NS\tIP\tLOC\tASN\tISP\trtt\tSerial\tDNSSEC\tValidFrom\tValidUntil\n")
	m := make(map[string][]NSInfo)
	for input := range wc {
		m[input.Name] = append(m[input.Name], input)
	}
	for _, info := range m {
		domainReport.NSInfo = append(domainReport.NSInfo, info...)
		i := 0
		var failed bool
		for _, ns := range info {
			if ns.Rtt == 0 {
				failed = true
			}
			// TODO output somewhere else
			// LAME servers
			auth := ""
			if ns.Msg != nil && !ns.Msg.Authoritative {
				auth = " L"
			}
			if failed {
				fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.Name, ns.IPInfo.IP.String()+auth, ns.Loc, ns.ASN, ns.ISP, "error", "error", "error")
				fmt.Fprintln(w)
				break
			}
			if ns.IPInfo.IP.To4() == nil {
				IPv6Guess = true
			}

			if i == 0 {
				fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.Name, ns.IPInfo.IP.String()+auth, ns.Loc, ns.ASN, fmt.Sprintf("%.40s", ns.ISP), ns.Rtt, ns.Serial)
			} else {
				fmt.Fprintf(w, "\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.IPInfo.IP.String()+auth, ns.Loc, ns.ASN, fmt.Sprintf("%.40s", ns.ISP), ns.Rtt, ns.Serial)
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
	flagQPS = flag.Int("qps", 10, "queries per seconds (per nameserver)")
	flagShowFail = flag.Bool("showfail", false, "only show checks that fail or warn")
	flagJSON = flag.Bool("json", false, "output in JSON")
	flag.StringVar(&resolver, "resolver", "8.8.8.8", "use this resolver for initial domain lookup")
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
	if !*flagJSON {
		fmt.Printf("using %s as resolver\n", resolver)
	}
	nsdataCache = make(map[string][]NSData)

	domain := flag.Arg(0)
	domainReport.Name = domain
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
	s.Writer = os.Stderr
	if *flagJSON || *flagDebug {
		s.Writer = ioutil.Discard
	}
	s.Start()

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
				res, err := query(domain, dns.TypeNS, ip.String(), true)
				if err == nil {
					valid, keyinfo, _ := validateRRSIG(keys, res.Msg.Answer)
					newnsinfo.DNSSECInfo = DNSSECInfo{Valid: valid, KeyInfo: keyinfo, ChainValid: chainValid}
					if keyinfo.Start == 0 && len(keys) == 0 {
						newnsinfo.Disabled = true
					}
				}
				newnsinfo.Msg = res.Msg
				wc <- newnsinfo
			}
			wg.Done()
		}(nsdata.Info)
	}

	wg.Wait()
	close(wc)
	s.Stop()
	<-done

	// enable debug again if needed
	if *flagDebug {
		log.Level = logrus.DebugLevel
	}

	if !IPv6Guess {
		nsdatas = removeIPv6(nsdatas)
	}

	s.Start()
	checkers := []Checker{
		&NSCheck{NS: nsdatas},
		&Glue{NS: nsdatas},
		&SOACheck{NS: nsdatas},
		&MXCheck{NS: nsdatas},
		&WebCheck{NS: nsdatas},
		&SpamCheck{NS: nsdatas}}

	// TODO concurrency
	for _, checker := range checkers {
		domainReport.Report = append(domainReport.Report, checker.CreateReport(domain))
	}

	if !*flagJSON {

		fmt.Println()
		for _, report := range domainReport.Report {
			for _, res := range report.Result {
				for _, record := range res.Records {
					fmt.Println(record)
				}
			}
		}
		fmt.Println()

		if !*flagShowFail {
			if chainErr != nil {
				fmt.Printf("DNSSEC\n\t FAIL: %s\n", chainErr)
			} else {
				fmt.Printf("DNSSEC\n\t OK  : DNSKEY validated. Chain validated\n")
			}

			for _, report := range domainReport.Report {
				fmt.Println(report.Type)
				for _, res := range report.Result {
					if res.Result != "" {
						fmt.Println("\t", res.Result)
					}
				}
			}
		} else {
			if chainErr != nil {
				fmt.Printf("DNSSEC\t FAIL: %s\n", chainErr)
			} else {
				fmt.Printf("DNSSEC\t OK  : DNSKEY validated. Chain validated\n")
			}
			for _, report := range domainReport.Report {
				for _, res := range report.Result {
					if res.Result != "" && res.Status == false {
						fmt.Println(report.Type, "\t", res.Result)
					}
				}
			}
		}
	}
	s.Stop()

	domainReport.Timestamp = time.Now()
	if *flagScan {
		domainReport.Scan = domainscan(domain)
	}
	if *flagJSON {
		res, err := json.Marshal(domainReport)
		if err != nil {
			fmt.Printf("encoding failed: %v\n", err)
		}
		fmt.Println(string(res))
	}
}
