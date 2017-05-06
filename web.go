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
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := WebData{Name: ns.Name, IP: nsip.String()}
			res, err := query("www."+domain, dns.TypeA, nsip.String(), true)
			if err != nil {
				c.Web = append(c.Web, data)
				break
			}
			data.A = extractRR(res.Msg.Answer, dns.TypeA)
			res, err = query("www."+domain, dns.TypeAAAA, nsip.String(), true)
			if err != nil {
				c.Web = append(c.Web, data)
				break
			}
			data.A = append(data.A, extractRR(res.Msg.Answer, dns.TypeAAAA)...)
			c.Web = append(c.Web, data)

			res, err = query(domain, dns.TypeA, nsip.String(), true)
			if err != nil {
				c.Web = append(c.Web, data)
				break
			}
			data.Apex = extractRR(res.Msg.Answer, dns.TypeA)
			data.Apex = append(data.Apex, extractRR(res.Msg.Answer, dns.TypeCNAME)...)
			res, err = query(domain, dns.TypeAAAA, nsip.String(), true)
			if err != nil {
				c.Web = append(c.Web, data)
				break
			}
			data.Apex = append(data.Apex, extractRR(res.Msg.Answer, dns.TypeAAAA)...)
			data.Apex = append(data.Apex, extractRR(res.Msg.Answer, dns.TypeCNAME)...)
			c.Web = append(c.Web, data)
		}
	}
}

func (c *WebCheck) CheckWww() []ReportResult {
	rep := []ReportResult{}
	for _, web := range c.Web {
		if len(web.A) > 0 {
			rep = append(rep, ReportResult{Result: ("OK  : Found a www record"),
				Status: true})
			break
		}
	}
	if len(rep) == 0 {
		rep = append(rep, ReportResult{Result: ("WARN: Didn't find a www record"),
			Status: false})
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
							Status: true})
						match = true
					}
				case *dns.CNAME:
					cmatch = true
					rep = append(rep, ReportResult{Result: ("WARN: Found a CNAME for the root record"),
						Status: false})
				}
				break
			}
		}
	}
	if len(rep) == 0 {
		rep = append(rep, ReportResult{Result: ("WARN: Didn't find a root record"),
			Status: false})
	}
	if !cmatch {
		rep = append(rep, ReportResult{Result: ("OK  : Didn't find a CNAME for the root record"),
			Status: true})
	}
	return rep
}

func (c *WebCheck) Values() []ReportResult {
	var results []ReportResult
	if !c.checkRFC1918() {
		results = append(results, ReportResult{Result: "OK  : Your www record has a public / routable address.",
			Status: true})
	} else {
		results = append(results, ReportResult{Result: "FAIL: Your www record has a non-routable (RFC1918) address.",
			Status: false})
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
