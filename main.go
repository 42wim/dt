package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/42wim/dt/check"
	"github.com/42wim/dt/scan"
	"github.com/42wim/dt/structs"
	"github.com/briandowns/spinner"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	flagScan, flagDebug, flagShowFail, flagJSON *bool
	flagQPS                                     *int
	log                                         = logrus.New()
	IPv6Guess                                   bool
)

func printHelp() {
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
}

func main() {
	var resolver string
	flagDebug = flag.Bool("debug", false, "enable debug")
	flagScan = flag.Bool("scan", false, "scan domain for common records")
	flagQPS = flag.Int("qps", 10, "queries per seconds (per nameserver)")
	flagShowFail = flag.Bool("showfail", false, "only show checks that fail or warn")
	flagJSON = flag.Bool("json", false, "output in JSON")
	flag.StringVar(&resolver, "resolver", "8.8.8.8", "use this resolver for initial domain lookup")
	flag.Parse()

	if len(flag.Args()) == 0 {
		printHelp()
		return
	}

	if *flagDebug {
		log.Level = logrus.DebugLevel
	}
	if !*flagJSON {
		fmt.Printf("using %s as resolver\n", resolver)
	}

	domain := flag.Arg(0)
	s := scan.New(&scan.Config{
		JSON:  flagJSON,
		Debug: flagDebug,
		QPS:   flagQPS,
	}, resolver)
	nsdatas, err := s.FindNS(dns.Fqdn(domain))
	if len(nsdatas) == 0 {
		fmt.Println("no nameservers found for", domain)
		os.Exit(1)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	createNSHeader(s, domain, nsdatas)

	// enable debug again if needed
	if *flagDebug {
		log.Level = logrus.DebugLevel
	}

	if !IPv6Guess {
		nsdatas = removeIPv6(nsdatas)
	}
	doDomainReport(s, domain, nsdatas)
}

func execCheckers(s *scan.Scan, domain string, nsdatas []structs.NSData, domainReport *check.DomainReport) {
	checkers := []check.Checker{
		check.NewNS(s, nsdatas),
		check.NewGlue(s, nsdatas),
		check.NewSOA(s, nsdatas),
		check.NewMX(s, nsdatas),
		check.NewWeb(s, nsdatas),
		check.NewSpam(s, nsdatas),
		check.NewDNSSEC(s, nsdatas),
	}

	// TODO concurrency
	for _, checker := range checkers {
		domainReport.Report = append(domainReport.Report, checker.CreateReport(domain))
	}
}

func doDomainReport(s *scan.Scan, domain string, nsdatas []structs.NSData) {
	var domainReport check.DomainReport
	domainReport.Name = domain
	sp := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	sp.Writer = os.Stderr
	if *flagJSON || *flagDebug {
		sp.Writer = ioutil.Discard
	}

	sp.Start()
	execCheckers(s, domain, nsdatas, &domainReport)

	if !*flagJSON {
		printDomainReport(domainReport, *flagShowFail)
	}
	sp.Stop()

	domainReport.Timestamp = time.Now()
	if *flagScan {
		sp := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		sp.Writer = os.Stderr
		if *flagJSON || *flagDebug {
			sp.Writer = ioutil.Discard
		}
		//        sp.Suffix = " Scanning... will take approx " + fmt.Sprintf("%#v seconds", float64(scanEntries/(len(servers)*(*s.QPS)))+float64(scanEntries)*avgRtt.Seconds())
		//t := time.Now()
		sp.Start()
		domainReport.Scan = s.DomainScan(domain)
		sp.Stop()
	}
	if *flagJSON {
		res, err := json.Marshal(domainReport)
		if err != nil {
			fmt.Printf("encoding failed: %v\n", err)
		}
		fmt.Println(string(res))
	}
}

func createNSHeader(s *scan.Scan, domain string, nsdatas []structs.NSData) {
	sp := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	sp.Writer = os.Stderr
	if *flagJSON || *flagDebug {
		sp.Writer = ioutil.Discard
	}
	sp.Start()

	wc := make(chan structs.NSInfo)
	done := make(chan struct{})
	var wg sync.WaitGroup
	go outputter(wc, done)

	// for now disable debuglevel (because of multiple goroutines output)
	if *flagDebug {
		log.Level = logrus.InfoLevel
	}

	for _, nsdata := range nsdatas {
		wg.Add(1)
		stubInfos := nsdata.Info
		go func() {
			for _, ns := range stubInfos {
				nsinfo, err := s.GetNSInfo(domain, ns.Name, ns.IP)
				if err != nil {
					continue
				}
				wc <- nsinfo
			}
			wg.Done()
		}()
	}

	wg.Wait()
	close(wc)
	sp.Stop()
	<-done
}
