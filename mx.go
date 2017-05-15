package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sort"
	"strings"
)

type MXCheck struct {
	NS     []NSData
	MX     []MXData
	MXIP   map[string][]net.IP // cache mx ip records
	MXIPRR map[string][]dns.RR // cache raw A/AAAA responses so we can extract CNAMEs if needed
	Report
}

type MXData struct {
	Name  string
	IP    string
	MX    []dns.RR
	Error string
}

func (c *MXCheck) Scan(domain string) {
	c.MXIP = make(map[string][]net.IP)
	c.MXIPRR = make(map[string][]dns.RR)
	log.Debugf("MX: scan")
	defer log.Debugf("MX: scan exit")
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := MXData{Name: ns.Name, IP: nsip.String()}
			mx, _, err := queryRRset(domain, dns.TypeMX, nsip.String(), true)
			if !scanerror(&c.Report, "MX scan", ns.Name, nsip.String(), domain, mx, err) {
				data.MX = mx
				for _, mxRR := range data.MX {
					mx := mxRR.(*dns.MX).Mx
					if _, ok := c.MXIP[mx]; !ok {
						res, err := query(dns.Fqdn(mx), dns.TypeA, resolver, true)
						if err != nil {
							break
						}
						c.MXIP[mx] = append(c.MXIP[mx], extractIP(res.Msg.Answer)...)
						c.MXIPRR[mx] = append(c.MXIPRR[mx], res.Msg.Answer...)
						res, err = query(dns.Fqdn(mx), dns.TypeAAAA, resolver, true)
						if err != nil {
							break
						}
						c.MXIP[mx] = append(c.MXIP[mx], extractIP(res.Msg.Answer)...)
						c.MXIPRR[mx] = append(c.MXIPRR[mx], res.Msg.Answer...)
					}
				}
				c.MX = append(c.MX, data)
			}
		}
	}
}

func (c *MXCheck) Identical() ReportResult {
	m := make(map[string][]string)
	for _, ns := range c.MX {
		mxstr := []string{}
		if ns.MX != nil {
			for _, mx := range ns.MX {
				mxstr = append(mxstr, mx.String()+"\n\t ")
			}
			sort.Strings(mxstr)
			m[strings.Join(mxstr, "")] = append(m[strings.Join(mxstr, "")], ns.IP)
		}
	}
	res := ReportResult{}
	if len(m) > 1 {
		res.Result = fmt.Sprintf("FAIL: MX not identical\n")
		res.Status = false
		res.Name = "Identical"
		for k, v := range m {
			res.Result += fmt.Sprintf("\t %s\n\t %s\n", v, k)
		}
	} else {
		res.Result = "OK  : MX of all nameservers are identical"
		res.Name = "Identical"
		res.Status = true
	}
	return res
}

func (c *MXCheck) checkRFC1918() bool {
	if len(c.MXIP) > 0 {
		for _, ips := range c.MXIP {
			for _, ip := range ips {
				if isRFC1918(ip) {
					return true
				}
			}
		}
	}
	return false
}

func (c *MXCheck) checkDuplicateIP() map[string][]string {
	m := make(map[string][]string)
	if len(c.MXIP) > 0 {
		for name, ips := range c.MXIP {
			for _, ip := range ips {
				m[ip.String()] = append(m[ip.String()], name)
			}
		}
	}
	return m
}

func (c *MXCheck) CheckCNAME() []ReportResult {
	log.Debugf("MX: cname")
	defer log.Debugf("MX: cname exit")
	rep := []ReportResult{}
	if len(c.MXIPRR) > 0 {
		for mxName, rrset := range c.MXIPRR {
			cname := extractRR(rrset, dns.TypeCNAME)
			if len(cname) > 0 {
				rep = append(rep, ReportResult{Result: fmt.Sprintf("FAIL: Your MX (%s) is a CNAME.", mxName),
					Status: false, Name: "CNAME"})
			}
		}
	}
	if len(rep) == 0 {
		rep = append(rep, ReportResult{Result: "OK  : No CNAMEs found for your MX records",
			Status: true, Name: "CNAME"})
	}
	return rep
}

func (c *MXCheck) CheckReverse() []ReportResult {
	log.Debugf("MX: reverse")
	defer log.Debugf("MX: reverse exit")
	rep := []ReportResult{}
	m := make(map[string]bool)
	if len(c.MXIP) > 0 {
		for name, ips := range c.MXIP {
			for _, ip := range ips {
				rev, _ := dns.ReverseAddr(ip.String())
				res, _, err := queryRRset(rev, dns.TypePTR, resolver, true)
				if err != nil {
					break
				}
				if len(res) > 0 {
					m[name] = true
				} else {
					m[name] = false
				}
			}
		}
	}
	for name, reverse := range m {
		if !reverse {
			rep = append(rep, ReportResult{Result: fmt.Sprintf("WARN: Reverse PTR lookup for MX %s failed.", name),
				Status: false, Name: "Reverse"})
		}
	}
	if len(rep) == 0 {
		rep = append(rep, ReportResult{Result: "OK  : All MX records have reverse PTR records",
			Status: true, Name: "Reverse"})
	}
	return rep
}

func (c *MXCheck) Values() []ReportResult {
	var results []ReportResult
	var rrset []dns.RR
	for _, ns := range c.MX {
		if ns.MX != nil {
			rrset = ns.MX
			break
		}
	}
	if len(rrset) > 1 {
		records := []string{}
		for _, rr := range rrset {
			records = append(records, rr.String())
		}
		results = append(results, ReportResult{Result: "OK  : Multiple MX records found",
			Status: true, Records: records, Name: "Multiple"})
	} else {
		results = append(results, ReportResult{Result: fmt.Sprintf("WARN: Only %v MX record found. Extra records increases reliability", len(rrset)),
			Status: false, Name: "Multiple"})
	}

	if !c.checkRFC1918() {
		results = append(results, ReportResult{Result: "OK  : Your MX records have public / routable addresses.",
			Status: true, Name: "RFC1918"})
	} else {
		results = append(results, ReportResult{Result: "FAIL: Some of your MX records have non-routable (RFC1918) addresses.",
			Status: false, Name: "RFC1918"})
	}

	m := c.checkDuplicateIP()
	duplicate := false
	for k, v := range m {
		if len(v) > 1 {
			results = append(results, ReportResult{Result: fmt.Sprintf("WARN: Same IP %s is used by multiple MX records %v.", k, v),
				Status: false, Name: "DuplicateIP"})
			duplicate = true
		}
	}
	if !duplicate {
		results = append(results, ReportResult{Result: "OK  : Your MX records resolve to different ips.",
			Status: true, Name: "DuplicateIP"})

	}
	return results
}

func (c *MXCheck) CreateReport(domain string) Report {
	c.Scan(domain)
	c.Report.Type = "MX"
	c.Report.Result = append(c.Report.Result, c.Identical())
	c.Report.Result = append(c.Report.Result, c.Values()...)
	c.Report.Result = append(c.Report.Result, c.CheckCNAME()...)
	c.Report.Result = append(c.Report.Result, c.CheckReverse()...)
	return c.Report
}
