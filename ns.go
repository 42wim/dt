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
	Name      string
	IP        string
	NS        []dns.RR
	CNAME     []dns.RR
	Error     string
	Auth      bool
	Recursive bool
}

func (c *NSCheck) Scan(domain string) {
	for _, ns := range c.NS {
		for _, nsip := range ns.IP {
			data := NSCheckData{Name: ns.Name, IP: nsip.String()}
			res, err := query(domain, dns.TypeNS, nsip.String(), true)
			rrset := extractRRMsg(res.Msg, dns.TypeNS)
			if !scanerror(&c.Report, "NS scan", ns.Name, nsip.String(), domain, rrset, err) {
				data.NS = rrset
				data.Auth = res.Msg.Authoritative
				data.Recursive = res.Msg.RecursionAvailable
			}
			c.NSCheck = append(c.NSCheck, data)
		}
	}
}

func (c *NSCheck) CheckCNAME() []ReportResult {
	rep := []ReportResult{}
	m := make(map[string]bool)
	for _, ns := range c.NSCheck {
		// skip lookup if already done
		if _, ok := m[ns.Name]; ok {
			break
		}
		// asking recursor for now
		res, err := query(dns.Fqdn(ns.Name), dns.TypeA, resolver, true)
		if err != nil {
			break
		}
		cname := extractRR(res.Msg.Answer, dns.TypeCNAME)
		if len(cname) > 0 {
			rep = append(rep, ReportResult{Result: fmt.Sprintf("FAIL: Your nameserver (%s) is a CNAME.", ns.Name),
				Status: false})
		}
		res, err = query(dns.Fqdn(ns.Name), dns.TypeAAAA, resolver, true)
		if err != nil {
			break
		}
		cname = extractRR(res.Msg.Answer, dns.TypeCNAME)
		if len(cname) > 0 {
			rep = append(rep, ReportResult{Result: fmt.Sprintf("FAIL: Your nameserver (%s) is a CNAME.", ns.Name),
				Status: false})
		}
		m[ns.Name] = true
	}
	if len(rep) == 0 {
		rep = append(rep, ReportResult{Result: "OK  : No CNAMEs found for your NS records",
			Status: true})
	}
	return rep
}

func (c *NSCheck) CheckParent(domain string) []ReportResult {
	var rep []ReportResult
	nsdata, err := findNS(getParentDomain(domain))
	if err != nil {
		return []ReportResult{}
	}
	var rrset []dns.RR
loop:
	for _, ns := range nsdata {
		for _, nsip := range ns.IP {
			res, err := query(dns.Fqdn(domain), dns.TypeNS, nsip.String(), true)
			if err != nil {
				break
			}
			rrset = extractRR(res.Msg.Ns, dns.TypeNS)
			if len(rrset) > 0 {
				break loop
			}
		}
	}
	m := make(map[string]bool)
	for _, rr := range rrset {
		m[dns.Fqdn(rr.(*dns.NS).Ns)] = true
	}
	missing := []string{}
	for _, ns := range c.NS {
		if _, ok := m[ns.Name]; !ok {
			missing = append(missing, ns.Name)
		} else {
			m[ns.Name] = false
		}

	}
	if len(missing) > 0 {
		rep = append(rep, ReportResult{Result: fmt.Sprintf("FAIL: The following nameservers are not listed as NS at the parent nameservers: %s", missing),
			Status: false})
	} else {
		rep = append(rep, ReportResult{Result: "OK  : Your nameservers are also listed as NS at the parent nameservers",
			Status: true})
	}

	// find the records that are sent by parent NS but arent in the domain NS
	missing = []string{}
	for k, v := range m {
		if v == true {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		rep = append(rep, ReportResult{Result: fmt.Sprintf("FAIL: The following nameservers are listed at the parent but not as NS at your nameservers: %s", missing),
			Status: false})
	} else {
		rep = append(rep, ReportResult{Result: "OK  : Your parent nameservers are also listed as NS at your nameservers",
			Status: true})
	}
	return rep
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

func (c *NSCheck) Recursive() []ReportResult {
	res := []ReportResult{}
	ok := true
	for _, ns := range c.NSCheck {
		if len(ns.NS) > 0 && ns.Recursive {
			res = append(res, ReportResult{Result: fmt.Sprintf("WARN: %s (%s) allows recursive queries.", ns.Name, ns.IP),
				Status: false})
			ok = false
		}
	}
	if ok {
		res = append(res, ReportResult{Result: "OK  : All nameservers report they are not allowing recursive queries.",
			Status: true})
	}
	return res
}

func (c *NSCheck) checkSameSubnet() bool {
	var ips []net.IP
	for _, ns := range c.NS {
		ips = append(ips, ns.IP...)
	}
	return isSameSubnet(ips...)
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
			Status: true, Records: records, Name: "Multiple"})
	} else {
		results = append(results, ReportResult{Result: fmt.Sprintf("WARN: Only %v nameserver found. Extra nameservers increases reliability", len(rrset)),
			Status: false, Name: "Multiple"})
	}

	for _, ns := range c.NSCheck {
		if ns.NS != nil {
			if len(ns.CNAME) > 1 {
				results = append(results, ReportResult{Result: fmt.Sprintf("FAIL: NS %s is a CNAME for %s", ns.Name, ns.CNAME[0].(*dns.CNAME).Target),
					Status: false, Name: "NSCNAME"})
			}
		}
	}
	if !c.checkSameSubnet() {
		results = append(results, ReportResult{Result: "OK  : Your nameservers are in different subnets.",
			Status: true, Name: "Subnet"})
	} else {
		results = append(results, ReportResult{Result: "WARN: Your nameservers are in the same subnet.",
			Status: false, Name: "Subnet"})
	}
	return results
}

func (c *NSCheck) CreateReport(domain string) Report {
	c.Scan(domain)
	c.Report.Type = "NS"
	c.Report.Result = append(c.Report.Result, c.Identical())
	c.Report.Result = append(c.Report.Result, c.Values()...)
	c.Report.Result = append(c.Report.Result, c.ASN())
	c.Report.Result = append(c.Report.Result, c.IPCheck()...)
	c.Report.Result = append(c.Report.Result, c.Auth()...)
	c.Report.Result = append(c.Report.Result, c.Recursive()...)
	c.Report.Result = append(c.Report.Result, c.CheckParent(domain)...)
	c.Report.Result = append(c.Report.Result, c.CheckCNAME()...)
	return c.Report
}
