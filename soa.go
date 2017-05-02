package main

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

type SOACheck struct {
	NS  []NSData
	SOA []SOAData
	Report
}

type SOAData struct {
	Name  string
	IP    string
	SOA   *dns.SOA
	Error string
}

func (c *SOACheck) Scan(domain string) {
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := SOAData{Name: ns.Name, IP: nsip.String()}
			soa, _, err := queryRRset(domain, dns.TypeSOA, nsip.String(), true)
			if err != nil {
				data.Error = fmt.Sprintf("SOA check failed on %s: %s", nsip.String(), err)
				c.SOA = append(c.SOA, data)
				break
			}
			if len(soa) == 0 {
				data.Error = fmt.Sprintf("SOA check failed on %s: %s", nsip.String(), "no records found")
				c.SOA = append(c.SOA, data)
				break
			}
			data.SOA = soa[0].(*dns.SOA)
			c.SOA = append(c.SOA, data)
		}
	}
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
		for k, v := range m {
			res.Result += fmt.Sprintf("\t %s\n\t %s\n", v, k)
		}
	} else {
		res.Result = "OK  : SOA of all nameservers are identical"
		res.Status = true
	}
	return res
}

func checkSerial(serial uint32) bool {
	serialstr := fmt.Sprintf("%v", serial)
	if len(serialstr) != 10 {
		return false
	}
	_, err := time.Parse("20060102", serialstr[:len(serialstr)-2])
	if err != nil {
		return false
	}
	return true
}

func (c *SOACheck) checkMname(mname string) bool {
	for _, ns := range c.NS {
		if mname == dns.Fqdn(ns.Name) {
			return true
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
			Status: true, Records: []string{soa.String()}})
	} else {
		results = append(results, ReportResult{Result: "WARN: Serial is not in the recommended format of YYYYMMDDnn.",
			Status: false})
	}
	if c.checkMname(soa.Ns) {
		results = append(results, ReportResult{Result: fmt.Sprintf("OK  : MNAME %s is listed at the parent servers.", soa.Ns),
			Status: true})
	} else {
		results = append(results, ReportResult{Result: fmt.Sprintf("FAIL: MNAME %s is not listed at the parent servers.", soa.Ns),
			Status: false})
	}
	return results
}

func (c *SOACheck) CreateReport(domain string) {
	c.Scan(domain)
	c.Report.Type = "SOA"
	c.Report.Result = append(c.Report.Result, c.Identical())
	c.Report.Result = append(c.Report.Result, c.Values()...)
}
