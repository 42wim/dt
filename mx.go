package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sort"
	"strings"
)

type MXCheck struct {
	NS []NSData
	MX []MXData
	Report
}

type MXData struct {
	Name  string
	IP    string
	MX    []dns.RR
	MXIP  map[string][]net.IP
	Error string
}

func (c *MXCheck) Scan(domain string) {
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := MXData{Name: ns.Name, IP: nsip.String(), MXIP: make(map[string][]net.IP)}
			mx, _, err := queryRRset(domain, dns.TypeMX, nsip.String(), true)
			if !scanerror(&c.Report, "MX scan", ns.Name, nsip.String(), domain, mx, err) {
				data.MX = mx
				// TODO only lookup once
				for _, mx := range data.MX {
					data.MXIP[mx.(*dns.MX).Mx] = append(data.MXIP[mx.(*dns.MX).Mx], getIP(mx.(*dns.MX).Mx, dns.TypeA, resolver)...)
					data.MXIP[mx.(*dns.MX).Mx] = append(data.MXIP[mx.(*dns.MX).Mx], getIP(mx.(*dns.MX).Mx, dns.TypeAAAA, resolver)...)
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
	for _, mx := range c.MX {
		if len(mx.MXIP) > 0 {
			for _, ips := range mx.MXIP {
				for _, ip := range ips {
					if isRFC1918(ip) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (c *MXCheck) checkDuplicateIP() map[string][]string {
	m := make(map[string][]string)
	for _, mx := range c.MX {
		if len(mx.MXIP) > 0 {
			for name, ips := range mx.MXIP {
				for _, ip := range ips {
					m[ip.String()] = append(m[ip.String()], name)
				}
			}
			break
		}
	}
	return m
}

func (c *MXCheck) CheckCNAME() []ReportResult {
	rep := []ReportResult{}
	m := make(map[string]bool)
	for _, mx := range c.MX {
		if len(mx.MX) > 0 {
			for mxName := range mx.MXIP {
				// skip lookup if already done
				if _, ok := m[mxName]; ok {
					break
				}
				res, err := query(dns.Fqdn(mxName), dns.TypeA, resolver, true)
				if err != nil {
					break
				}
				cname := extractRR(res.Msg.Answer, dns.TypeCNAME)
				if len(cname) > 0 {
					rep = append(rep, ReportResult{Result: fmt.Sprintf("FAIL: Your MX (%s) is a CNAME.", mxName),
						Status: false, Name: "CNAME"})
				}
				res, err = query(dns.Fqdn(mxName), dns.TypeAAAA, resolver, true)
				if err != nil {
					break
				}
				cname = extractRR(res.Msg.Answer, dns.TypeCNAME)
				if len(cname) > 0 {
					rep = append(rep, ReportResult{Result: fmt.Sprintf("FAIL: Your MX (%s) is a CNAME.", mxName),
						Status: false, Name: "CNAME"})
				}
				m[mxName] = true
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
	rep := []ReportResult{}
	m := make(map[string]bool)
	for _, mx := range c.MX {
		if len(mx.MXIP) > 0 {
			for name, ips := range mx.MXIP {
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
			break
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
