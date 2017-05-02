package main

import (
	"fmt"
	"github.com/miekg/dns"
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
	Error string
}

func (c *MXCheck) Scan(domain string) {
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := MXData{Name: ns.Name, IP: nsip.String()}
			mx, _, err := queryRRset(domain, dns.TypeMX, nsip.String(), true)
			if err != nil {
				data.Error = fmt.Sprintf("MX check failed on %s: %s", nsip.String(), err)
				c.MX = append(c.MX, data)
				break
			}
			if len(mx) == 0 {
				data.Error = fmt.Sprintf("MX check failed on %s: %s", nsip.String(), "no records found")
				c.MX = append(c.MX, data)
				break
			}
			data.MX = mx
			c.MX = append(c.MX, data)
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
		}
		sort.Strings(mxstr)
		m[strings.Join(mxstr, "")] = append(m[strings.Join(mxstr, "")], ns.IP)
	}
	res := ReportResult{}
	if len(m) > 1 {
		res.Result = fmt.Sprintf("FAIL: MX not identical\n")
		res.Status = false
		for k, v := range m {
			res.Result += fmt.Sprintf("\t %s\n\t %s\n", v, k)
		}
	} else {
		res.Result = "OK  : MX of all nameservers are identical"
		res.Status = true
	}
	return res
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
			Status: true, Records: records})
	} else {
		results = append(results, ReportResult{Result: fmt.Sprintf("WARN: Only %v MX record found. Extra records increases reliability", len(rrset)),
			Status: false})
	}

	//TODO
	// cname check
	// duplicate IP check
	// rfc1918 check
	// multiple subnets
	return results
}

func (c *MXCheck) CreateReport(domain string) {
	c.Scan(domain)
	c.Report.Type = "MX"
	c.Report.Result = append(c.Report.Result, c.Identical())
	c.Report.Result = append(c.Report.Result, c.Values()...)
}
