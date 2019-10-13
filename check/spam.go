package check

import (
	"strings"

	"github.com/42wim/dt/scan"
	"github.com/42wim/dt/structs"
	"github.com/miekg/dns"
)

type SpamCheck struct {
	NS   []structs.NSData
	Spam []SpamData
	Report
	s *scan.Scan
}

type SpamData struct {
	Name  string
	IP    string
	Dmarc []dns.RR
	Spf   []dns.RR
	Error string
}

func NewSpam(s *scan.Scan, ns []structs.NSData) *SpamCheck {
	c := &SpamCheck{
		s:  s,
		NS: ns,
	}
	return c
}

func (c *SpamCheck) Scan(domain string) {
	c.ScanDmarc(domain)
	c.ScanSpf(domain)
}

func (c *SpamCheck) ScanDmarc(domain string) {
	log.Debugf("Spam: scan")
	defer log.Debugf("Spam: scan exit")
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := SpamData{Name: ns.Name, IP: nsip.String()}
			dmarc, _, err := scan.QueryRRset("_dmarc."+domain, dns.TypeTXT, nsip.String(), true)
			if !c.Report.scanError("DMARC scan", ns.Name, nsip.String(), domain, dmarc, err) {
				data.Dmarc = dmarc
				c.Spam = append(c.Spam, data)
			}
		}
	}
}

func (c *SpamCheck) ScanSpf(domain string) {
	log.Debugf("Spam: scanspf")
	defer log.Debugf("Spam: scanspf exit")
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := SpamData{Name: ns.Name, IP: nsip.String()}
			txt, _, err := scan.QueryRRset(domain, dns.TypeTXT, nsip.String(), true)
			if !c.Report.scanError("SPF scan", ns.Name, nsip.String(), domain, txt, err) {
				spf := []dns.RR{}
				for _, rr := range txt {
					if strings.Contains(rr.String(), "v=spf") {
						spf = append(spf, rr)
					}
				}
				data.Spf = spf
				c.Spam = append(c.Spam, data)
			}
		}
	}
}

func (c *SpamCheck) Values() []ReportResult {
	var results []ReportResult
	var rrset []dns.RR
	for _, ns := range c.Spam {
		if ns.Dmarc != nil {
			rrset = ns.Dmarc
			break
		}
	}
	if len(rrset) > 0 {
		results = append(results, ReportResult{Result: "OK  : DMARC records found.",
			Status: true, Name: "DMARC"})
		records := []string{}
		for _, rr := range rrset {
			records = append(records, rr.String())
			if strings.Contains(rr.String(), "p=none") {
				results = append(results, ReportResult{Result: "WARN: DMARC with monitoring policy found.",
					Status: false, Name: "DMARCPolicy"})
			}
			if strings.Contains(rr.String(), "p=quarantine") {
				results = append(results, ReportResult{Result: "WARN: DMARC with quarantine policy found.",
					Status: false, Name: "DMARCPolicy"})
			}
			if strings.Contains(rr.String(), "p=reject") {
				results = append(results, ReportResult{Result: "OK  : DMARC with reject policy.",
					Status: true, Name: "DMARCPolicy"})
			}
		}
		results = append(results, ReportResult{Status: true, Records: records})
	} else {
		results = append(results, ReportResult{Result: "WARN: No DMARC records found. Along with DKIM and SPF, DMARC helps prevent spam from your domain.",
			Status: false, Name: "DMARC"})
	}

	for _, ns := range c.Spam {
		if ns.Spf != nil {
			rrset = ns.Spf
			break
		}
	}

	if len(rrset) > 0 {
		records := []string{}
		for _, rr := range rrset {
			records = append(records, rr.String())
		}
		results = append(results, ReportResult{Result: "OK  : SPF records found.",
			Status: true, Records: records, Name: "SPF"})
	} else {
		results = append(results, ReportResult{Result: "WARN: No SPF records found. Along with DKIM and DMARC, SPF helps prevent spam from your domain.",
			Status: false, Name: "SPF"})
	}

	for _, rr := range rrset {
		if strings.Contains(rr.String(), "-all") {
			results = append(results, ReportResult{Result: "OK  : SPF records set up restrictively.",
				Status: true, Name: "SPF"})
		}
		if strings.Contains(rr.String(), "~all") {
			results = append(results, ReportResult{Result: "WARN: SPF record set to softfail.",
				Status: true, Name: "SPF"})
		}
		if strings.Contains(rr.String(), " ptr ") || strings.Contains(rr.String(), " ptr:") {
			results = append(results, ReportResult{Result: "WARN: SPF record uses ptr mechanism (see RFC7208 5.5).",
				Status: true, Name: "SPF"})
		}
	}

	// TODO
	// dmarc: p=none recommendation?
	// spf: further recommendations ?

	return results
}

func (c *SpamCheck) CreateReport(domain string) Report {
	c.Scan(domain)
	c.Report.Type = "Spam"
	c.Report.Result = append(c.Report.Result, c.Values()...)
	return c.Report
}
