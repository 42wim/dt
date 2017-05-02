package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sort"
	"strings"
)

type NSCheck struct {
	NS      []NSData
	NSCheck []NSCheckData
	Report
}

type NSCheckData struct {
	Name  string
	IP    string
	NS    []dns.RR
	Error string
	Auth  bool
}

func (c *NSCheck) Scan(domain string) {
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := NSCheckData{Name: ns.Name, IP: nsip.String()}
			res, err := query(domain, dns.TypeNS, nsip.String(), true)
			if err != nil {
				data.Error = fmt.Sprintf("NS check failed on %s: %s", nsip.String(), err)
				c.NSCheck = append(c.NSCheck, data)
				break
			}
			nsrr := extractRR(res.Msg.Answer, dns.TypeNS)
			if len(nsrr) == 0 {
				data.Error = fmt.Sprintf("NSCheck check failed on %s: %s", nsip.String(), "no records found")
				data.NS = nsrr
				data.Auth = res.Msg.Authoritative
				c.NSCheck = append(c.NSCheck, data)
				break
			}
			data.NS = nsrr
			data.Auth = res.Msg.Authoritative
			c.NSCheck = append(c.NSCheck, data)
		}
	}
}

func (c *NSCheck) Identical() ReportResult {
	m := make(map[string][]string)
	for _, ns := range c.NSCheck {
		nsstr := []string{}
		if ns.NS != nil && ns.Error == "" {
			for _, nsc := range ns.NS {
				nsstr = append(nsstr, nsc.String()+"\n\t ")
			}
			sort.Strings(nsstr)
			m[strings.Join(nsstr, "")] = append(m[strings.Join(nsstr, "")], ns.IP)
		}
	}
	res := ReportResult{}
	if len(m) > 1 {
		res.Result = fmt.Sprintf("FAIL: NS not identical\n")
		res.Status = false
		for k, v := range m {
			res.Result += fmt.Sprintf("\t %s\n\t %s\n", v, k)
		}
	} else {
		res.Result = "OK  : NS of all nameservers are identical"
		res.Status = true
	}
	return res
}

func (c *NSCheck) ASN() ReportResult {
	m := make(map[string][]string)
	for _, ns := range c.NSCheck {
		ip := net.ParseIP(ns.IP)
		info, _ := ipinfo(ip)
		m[info.ASN.String()] = append(m[info.ASN.String()], ns.IP)
	}
	res := ReportResult{}
	if len(m) > 1 {
		res.Result = "OK  : Nameservers are spread over multiple AS"
		res.Status = true
	} else {
		as := ""
		for k := range m {
			as = k
			break
		}
		res.Result = fmt.Sprintf("WARN: Nameservers are all on the same AS (%s). This is a single point of failure.", as)
		res.Status = false
	}
	return res
}

func (c *NSCheck) IPCheck() []ReportResult {
	m := make(map[string]int)
	for _, ns := range c.NSCheck {
		if strings.Contains(ns.IP, ":") {
			m["ipv6"]++
		} else {
			m["ipv4"]++
		}
	}

	res := []ReportResult{}
	if m["ipv6"] == 0 {
		res = append(res, ReportResult{Result: "WARN: No IPv6 nameservers found. IPv6-only users will have problems.",
			Status: false})
	}

	// I wonder when this will ever happen :)
	if m["ipv4"] == 0 {
		res = append(res, ReportResult{Result: "WARN: No IPv4 nameservers found. IPv4-only users will have problems.",
			Status: false})
	}
	if (m["ipv4"] > 0) && (m["ipv6"] > 0) {
		res = append(res, ReportResult{Result: "OK  : IPv4 and IPv6 nameservers found.",
			Status: true})
	}
	return res
}

func (c *NSCheck) Auth() []ReportResult {
	res := []ReportResult{}
	ok := true
	for _, ns := range c.NSCheck {
		if len(ns.NS) > 0 && !ns.Auth {
			res = append(res, ReportResult{Result: fmt.Sprintf("FAIL: %s (%s) is not authoritative.", ns.Name, ns.IP),
				Status: false})
			ok = false
		}
	}
	if ok {
		res = append(res, ReportResult{Result: "OK  : All nameservers are authoritative.",
			Status: true})
	}
	return res
}

func (c *NSCheck) Values() []ReportResult {
	var results []ReportResult
	var rrset []dns.RR
	for _, ns := range c.NSCheck {
		if ns.NS != nil {
			rrset = ns.NS
			break
		}
	}
	if len(rrset) > 1 {
		records := []string{}
		for _, rr := range rrset {
			records = append(records, rr.String())
		}
		results = append(results, ReportResult{Result: "OK  : Multiple nameservers found",
			Status: true, Records: records})
	} else {
		results = append(results, ReportResult{Result: fmt.Sprintf("WARN: Only %v nameserver found. Extra nameservers increases reliability", len(rrset)),
			Status: false})
	}
	return results

	//TODO
	// check NS at parent, compare with domain NS
	// check if NS actually response
	// stealth records

}

func (c *NSCheck) CreateReport(domain string) {
	c.Scan(domain)
	c.Report.Type = "NS"
	c.Report.Result = append(c.Report.Result, c.Identical())
	c.Report.Result = append(c.Report.Result, c.Values()...)
	c.Report.Result = append(c.Report.Result, c.ASN())
	c.Report.Result = append(c.Report.Result, c.IPCheck()...)
	c.Report.Result = append(c.Report.Result, c.Auth()...)
}
