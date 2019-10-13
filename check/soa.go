package check

import (
	"fmt"
	"time"

	"github.com/42wim/dt/scan"
	"github.com/42wim/dt/structs"
	"github.com/miekg/dns"
)

type SOACheck struct {
	NS     []structs.NSData
	SOA    []SOAData
	Domain string
	Report
	s *scan.Scan
}

type SOAData struct {
	Name  string
	IP    string
	SOA   *dns.SOA
	Error string
}

func NewSOA(s *scan.Scan, ns []structs.NSData) *SOACheck {
	c := &SOACheck{
		s:  s,
		NS: ns,
	}
	return c
}

func (c *SOACheck) Scan(domain string) {
	log.Debugf("SOA: scan")
	defer log.Debugf("SOA: scan exit")
	c.Domain = domain
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := SOAData{Name: ns.Name, IP: nsip.String()}
			soa, _, err := scan.QueryRRset(domain, dns.TypeSOA, nsip.String(), true)
			if !c.Report.scanError("SOA scan", ns.Name, nsip.String(), domain, soa, err) {
				data.SOA = soa[0].(*dns.SOA)
			} else {
				data.Error = err.Error()
			}
			c.SOA = append(c.SOA, data)
		}
	}
}

func (c *SOACheck) checkMname(mname string) bool {
	log.Debugf("SOA: mname")
	defer log.Debugf("SOA: mname exit")
	nsdata, err := c.s.FindNS(getParentDomain(c.Domain))
	if err != nil {
		return false
	}
	var rrset []dns.RR
loop:
	for _, ns := range nsdata {
		for _, nsip := range ns.IP {
			res, err := scan.Query(dns.Fqdn(c.Domain), dns.TypeNS, nsip.String(), true)
			if err != nil {
				break
			}
			rrset = extractRR(res.Msg.Ns, dns.TypeNS)
			if len(rrset) > 0 {
				break loop
			}
		}
	}
	for _, pns := range rrset {
		if pns.(*dns.NS).Ns == mname {
			return true
		}
	}
	return false
}

func (c *SOACheck) Identical() ReportResult {
	m := make(map[string][]string)
	for _, ns := range c.SOA {
		if ns.SOA != nil {
			m[ns.SOA.String()] = append(m[ns.SOA.String()], ns.Name+"("+ns.IP+")")
		}
	}
	res := ReportResult{}
	if len(m) > 1 {
		res.Result = fmt.Sprintf("FAIL: SOA not identical\n")
		res.Status = false
		res.Name = "Identical"
		for k, v := range m {
			res.Result += fmt.Sprintf("\t %s\n\t %s\n", v, k)
		}
	} else {
		res.Result = "OK  : SOA of all nameservers are identical"
		res.Status = true
		res.Name = "Identical"
	}
	return res
}

func checkSerial(serial uint32) bool {
	serialstr := fmt.Sprintf("%v", serial)
	if len(serialstr) != 10 {
		return false
	}
	_, err := time.Parse("20060102", serialstr[:len(serialstr)-2])
	return err != nil
}

func (c *SOACheck) checkRFC1918() bool {
	for _, ns := range c.NS {
		for _, ip := range ns.IP {
			if isRFC1918(ip) {
				return true
			}
		}
	}
	return false
}

func (c *SOACheck) Values() []ReportResult {
	var soa *dns.SOA
	var results []ReportResult
	for _, ns := range c.SOA {
		if ns.SOA != nil {
			soa = ns.SOA
		}
	}
	if checkSerial(soa.Serial) {
		results = append(results, ReportResult{Result: "OK  : Serial format appears to be in the recommended format of YYYYMMDDnn.",
			Status: true, Records: []string{soa.String()}, Name: "Serial"})
	} else {
		results = append(results, ReportResult{Result: "WARN: Serial is not in the recommended format of YYYYMMDDnn.",
			Status: false, Name: "Serial"})
	}
	if c.checkMname(soa.Ns) {
		results = append(results, ReportResult{Result: fmt.Sprintf("OK  : MNAME %s is listed at the parent servers.", soa.Ns),
			Status: true, Name: "MNAME"})
	} else {
		results = append(results, ReportResult{Result: fmt.Sprintf("FAIL: MNAME %s is not listed at the parent servers.", soa.Ns),
			Status: false, Name: "MNAME"})
	}
	if !c.checkRFC1918() {
		results = append(results, ReportResult{Result: "OK  : Your nameservers have public / routable addresses.",
			Status: true, Name: "RFC1918"})
	} else {
		results = append(results, ReportResult{Result: "FAIL: Some of your nameservers have non-routable (RFC1918) addresses.",
			Status: false, Name: "RFC1918"})
	}
	return results
}

func (c *SOACheck) CreateReport(domain string) Report {
	c.Scan(domain)
	c.Report.Type = "SOA"
	c.Report.Result = append(c.Report.Result, c.Identical())
	c.Report.Result = append(c.Report.Result, c.Values()...)
	return c.Report
}
