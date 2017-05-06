package main

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

type SpamCheck struct {
	NS   []NSData
	Spam []SpamData
	Report
}

type SpamData struct {
	Name  string
	IP    string
	Dmarc []dns.RR
	Spf   []dns.RR
	Error string
}

func (c *SpamCheck) Scan(domain string) {
	c.ScanDmarc(domain)
	c.ScanSpf(domain)
}

func (c *SpamCheck) ScanDmarc(domain string) {
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := SpamData{Name: ns.Name, IP: nsip.String()}
			dmarc, _, err := queryRRset("_dmarc."+domain, dns.TypeTXT, nsip.String(), true)
			if err != nil {
				data.Error = fmt.Sprintf("dmarc check failed on %s: %s", nsip.String(), err)
				c.Spam = append(c.Spam, data)
				break
			}
			if len(dmarc) == 0 {
				data.Error = fmt.Sprintf("dmarc check failed on %s: %s", nsip.String(), "no records found")
				c.Spam = append(c.Spam, data)
				break
			}
			data.Dmarc = dmarc
			c.Spam = append(c.Spam, data)
		}
	}
}

func (c *SpamCheck) ScanSpf(domain string) {
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := SpamData{Name: ns.Name, IP: nsip.String()}
			txt, _, err := queryRRset(domain, dns.TypeTXT, nsip.String(), true)
			if err != nil {
				data.Error = fmt.Sprintf("spf check failed on %s: %s", nsip.String(), err)
				c.Spam = append(c.Spam, data)
				break
			}
			spf := []dns.RR{}
			for _, rr := range txt {
				if strings.Contains(rr.String(), "v=spf") {
					spf = append(spf, rr)
				}
			}
			if len(spf) == 0 {
				data.Error = fmt.Sprintf("spf check failed on %s: %s", nsip.String(), "no records found")
				c.Spam = append(c.Spam, data)
				break
			}
			data.Spf = spf
			c.Spam = append(c.Spam, data)
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
			Status: true})
		records := []string{}
		for _, rr := range rrset {
			records = append(records, rr.String())
			if strings.Contains(rr.String(), "p=none") {
				results = append(results, ReportResult{Result: "WARN: DMARC with monitoring policy found.",
					Status: false})
			}
			if strings.Contains(rr.String(), "p=quarantine") {
				results = append(results, ReportResult{Result: "WARN: DMARC with quarantine policy found.",
					Status: false})
			}
			if strings.Contains(rr.String(), "p=reject") {
				results = append(results, ReportResult{Result: "OK  : DMARC with reject policy.",
					Status: false})
			}
		}
		results = append(results, ReportResult{Status: true, Records: records})
	} else {
		results = append(results, ReportResult{Result: "WARN: No DMARC records found. Along with DKIM and SPF, DMARC helps prevent spam from your domain.",
			Status: false})
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
			Status: true, Records: records})
	} else {
		results = append(results, ReportResult{Result: "WARN: No SPF records found. Along with DKIM and DMARC, SPF helps prevent spam from your domain.",
			Status: false})
	}

	for _, rr := range rrset {
		if strings.Contains(rr.String(), "-all") || strings.Contains(rr.String(), "~all") {
			results = append(results, ReportResult{Result: "OK  : SPF records set up restrictively.",
				Status: true})
		}
		break
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
