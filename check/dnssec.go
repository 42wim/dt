package check

import (
	"github.com/42wim/dt/scan"
	"github.com/42wim/dt/structs"
)

type DNSSECCheck struct {
	NS     []structs.NSData
	DNSSEC []DNSSECCheckData
	Report
	s *scan.Scan
}

type DNSSECCheckData struct {
	Name  string
	IP    string
	Error string
	Valid bool
}

func NewDNSSEC(s *scan.Scan, ns []structs.NSData) *DNSSECCheck {
	c := &DNSSECCheck{
		s:  s,
		NS: ns,
	}

	return c
}

func (c *DNSSECCheck) Scan(domain string) {
	log.Debugf("DNSSEC: scan")
	defer log.Debugf("DNSSEC: scan exit")

	_, err := c.s.ValidateChain(domain)
	if err != nil {
		c.DNSSEC = append(c.DNSSEC, DNSSECCheckData{Error: err.Error()})
		return
	}

	c.DNSSEC = append(c.DNSSEC, DNSSECCheckData{Valid: true})
}

func (c *DNSSECCheck) Values() []ReportResult {
	var results []ReportResult

	for _, res := range c.DNSSEC {
		if res.Valid {
			results = append(results, ReportResult{
				Result: "OK  : DNSKEY validated. Chain validated",
				Status: true, Name: "DNSSEC",
			})
		} else {
			results = append(results, ReportResult{
				Result: "FAIL: " + res.Error,
				Status: false, Name: "DNSSEC",
			})
		}
	}

	return results
}

func (c *DNSSECCheck) CreateReport(domain string) Report {
	c.Scan(domain)

	c.Report.Type = "DNSSEC"
	c.Report.Result = append(c.Report.Result, c.Values()...)

	return c.Report
}
