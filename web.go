package main

import "github.com/miekg/dns"

type WebCheck struct {
	NS  []NSData
	Web []WebData
	Report
}

type WebData struct {
	Name  string
	IP    string
	A     []dns.RR
	Apex  []dns.RR
	Error string
}

func (c *WebCheck) Scan(domain string) {
	log.Debugf("Web: scan")
	defer log.Debugf("Web: scan exit")
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := WebData{Name: ns.Name, IP: nsip.String()}
			// www
			rrset, _, err := queryRRset("www."+domain, dns.TypeA, nsip.String(), true)
			if !scanerror(&c.Report, "WWW ipv4 scan", ns.Name, nsip.String(), domain, rrset, err) {
				data.A = append(data.A, rrset...)
			}
			rrset, _, err = queryRRset("www."+domain, dns.TypeAAAA, nsip.String(), true)
			if !scanerror(&c.Report, "WWW ipv6 scan", ns.Name, nsip.String(), domain, rrset, err) {
				data.A = append(data.A, rrset...)
			}
			// apex
			res, err := query(domain, dns.TypeA, nsip.String(), true)
			rrset = extractRRMsg(res.Msg, dns.TypeA)
			if !scanerror(&c.Report, "root ipv4 scan", ns.Name, nsip.String(), domain, rrset, err) {
				data.Apex = append(data.Apex, rrset...)
				data.Apex = append(data.Apex, extractRR(res.Msg.Answer, dns.TypeCNAME)...)
			}
			res, err = query(domain, dns.TypeAAAA, nsip.String(), true)
			rrset = extractRRMsg(res.Msg, dns.TypeAAAA)
			if !scanerror(&c.Report, "root ipv6 scan", ns.Name, nsip.String(), domain, rrset, err) {
				data.Apex = append(data.Apex, rrset...)
				data.Apex = append(data.Apex, extractRR(res.Msg.Answer, dns.TypeCNAME)...)
			}
			c.Web = append(c.Web, data)
		}
	}
}

func (c *WebCheck) CheckWww() []ReportResult {
	rep := []ReportResult{}
	for _, web := range c.Web {
		if len(web.A) > 0 {
			rep = append(rep, ReportResult{Result: ("OK  : Found a www record"),
				Status: true, Name: "WWW"})
			break
		}
	}
	if len(rep) == 0 {
		rep = append(rep, ReportResult{Result: ("WARN: Didn't find a www record"),
			Status: false, Name: "WWW"})
	}
	return rep
}

func (c *WebCheck) checkRFC1918() bool {
	for _, web := range c.Web {
		ips := extractIP(web.A)
		if len(ips) > 0 {
			for _, ip := range ips {
				if isRFC1918(ip) {
					return true
				}
			}
		}
	}
	return false
}

func (c *WebCheck) CheckApex() []ReportResult {
	rep := []ReportResult{}
	match := false
	cmatch := false
	for _, web := range c.Web {
		if len(web.Apex) > 0 {
			for _, rr := range web.Apex {
				switch rr.(type) {
				case *dns.A, *dns.AAAA:
					if !match {
						rep = append(rep, ReportResult{Result: ("OK  : Found a root record"),
							Status: true, Name: "Apex"})
						match = true
					}
				case *dns.CNAME:
					cmatch = true
					rep = append(rep, ReportResult{Result: ("WARN: Found a CNAME for the root record"),
						Status: false, Name: "ApexCNAME"})
				}
				break
			}
		}
	}
	if len(rep) == 0 {
		rep = append(rep, ReportResult{Result: ("WARN: Didn't find a root record"),
			Status: false, Name: "Apex"})
	}
	if !cmatch {
		rep = append(rep, ReportResult{Result: ("OK  : Didn't find a CNAME for the root record"),
			Status: true, Name: "ApexCNAME"})
	}
	return rep
}

func (c *WebCheck) Values() []ReportResult {
	var results []ReportResult
	if !c.checkRFC1918() {
		results = append(results, ReportResult{Result: "OK  : Your www record has a public / routable address.",
			Status: true, Name: "RFC1918"})
	} else {
		results = append(results, ReportResult{Result: "FAIL: Your www record has a non-routable (RFC1918) address.",
			Status: false, Name: "RFC1918"})
	}
	return results
}

func (c *WebCheck) CreateReport(domain string) Report {
	c.Scan(domain)
	c.Report.Type = "Web"
	c.Report.Result = append(c.Report.Result, c.CheckWww()...)
	c.Report.Result = append(c.Report.Result, c.CheckApex()...)
	c.Report.Result = append(c.Report.Result, c.Values()...)
	return c.Report
}
