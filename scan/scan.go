package scan

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/42wim/dt/structs"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()
var DSP = []struct {
	Qtype   uint16
	Entries []string
}{
	{dns.TypeSOA, []string{""}},
	{dns.TypeNS, []string{""}},
	{dns.TypeDS, []string{""}},
	{dns.TypeDNSKEY, []string{""}},
	{dns.TypeMX, []string{""}},
	{dns.TypeCAA, []string{""}},
	{dns.TypeTXT, []string{"", "_amazonses.", "_dmarc.", "api.", "api._domainkey.", "cm._domainkey.", "default.", "default._domainkey.", "dk._domainkey.", "googleapps._domainkey.", "mail._domainkey.", "mailjet.", "mesmtp._domainkey."}},
	{dns.TypeA, []string{"", "_dmarc.", "admin.", "administration.", "ads.", "adserver.", "alerts.", "alpha.", "analytics.", "ap.", "apache.", "app.", "apps.", "appserver.", "auth.", "autodiscover.", "backup.", "beta.", "blog.", "calendar.", "cdn.", "cdn.", "chat.", "citrix.", "clients.", "cms.", "confluence.", "corp.", "corp.", "crs.", "cvs.", "database.", "db.", "demo.", "dev.", "devel.", "development.", "devsql.", "dhcp.", "direct.", "dmz.", "dns.", "dns0.", "dns00.", "dns01.", "dns010.", "dns02.", "dns03.", "dns04.", "dns05.", "dns06.", "dns07.", "dns08.", "dns09.", "dns1.", "dns10.", "dns2.", "dns3.", "dns4.", "dns5.", "dns6.", "dns7.", "dns8.", "dns9.", "download.", "emergency.", "en.", "enterpriseenrollment.", "enterpriseregistration.", "erp.", "eshop.", "exchange.", "f5.", "fileserver.", "firewall.", "forum.", "ftp.", "gateway.", "gc.", "git.", "gw.", "help.", "home.", "host.", "http.", "id.", "images.", "imap.", "imap4.", "info.", "internal.", "internet.", "intranet.", "ipv6.", "jenkins.", "jira.", "lab.", "lb0.", "lb00.", "lb01.", "lb010.", "lb02.", "lb03.", "lb04.", "lb05.", "lb06.", "lb07.", "lb08.", "lb09.", "lb1.", "lb10.", "lb2.", "lb3.", "lb4.", "lb5.", "lb6.", "lb7.", "lb8.", "lb9.", "ldap.", "linux.", "local.", "log.", "log.", "lyncdiscover.", "mail.", "mail0.", "mail00.", "mail01.", "mail010.", "mail02.", "mail03.", "mail04.", "mail05.", "mail06.", "mail07.", "mail08.", "mail09.", "mail1.", "mail10.", "mail2.", "mail3.", "mail4.", "mail5.", "mail6.", "mail7.", "mail8.", "mail9.", "mailgate.", "mailing.", "main.", "manage.", "mgmt.", "mirror.", "mobile.", "monitor.", "msoid.", "mssql.", "mta.", "mx.", "mx0.", "mx00.", "mx01.", "mx010.", "mx02.", "mx03.", "mx04.", "mx05.", "mx06.", "mx07.", "mx08.", "mx09.", "mx1.", "mx10.", "mx2.", "mx3.", "mx4.", "mx5.", "mx6.", "mx7.", "mx8.", "mx9.", "mysql-master.", "mysql-slave.", "mysql.", "new.", "news.", "noc.", "ns.", "ns0.", "ns00.", "ns01.", "ns010.", "ns02.", "ns03.", "ns04.", "ns05.", "ns06.", "ns07.", "ns08.", "ns09.", "ns1.", "ns10.", "ns2.", "ns3.", "ns4.", "ns5.", "ns6.", "ns7.", "ns8.", "ns9.", "ntp.", "office.", "ops.", "oracle.", "owa.", "pbx.", "piwik.", "pop.", "pop3.", "preprod.", "prod.", "production.", "projects.", "rdp.", "remote.", "robot.", "safe.", "secure.", "server.", "shop.", "sip.", "smtp.", "sql.", "sql0.", "sql00.", "sql01.", "sql010.", "sql02.", "sql03.", "sql04.", "sql05.", "sql06.", "sql07.", "sql08.", "sql09.", "sql1.", "sql10.", "sql2.", "sql3.", "sql4.", "sql5.", "sql6.", "sql7.", "sql8.", "sql9.", "squid.", "ssh.", "ssl.", "stage.", "staging.", "stats.", "support.", "svn.", "syslog.", "test.", "testing.", "upload.", "val.", "vm.", "vnc.", "voip.", "vpn.", "web0.", "web00.", "web01.", "web010", "web02.", "web03.", "web04.", "web05.", "web06.", "web07.", "web08.", "web09.", "web1.", "web10.", "web2.", "web3.", "web4.", "web5.", "web6.", "web7.", "web8.", "web9.", "webmail.", "webshop.", "whois.", "wiki.", "www.", "xml."}},
	{dns.TypeSRV, []string{"_afpovertcp._tcp.", "_autodiscover._tcp.", "_caldav._tcp.", "_client._smtp.", "_gc._tcp.", "_h323cs._tcp.", "_h323cs._udp.", "_h323ls._tcp.", "_h323ls._udp.", "_h323rs._tcp.", "_h323rs._tcp.", "_http._tcp.", "_iax.udp.", "_imap._tcp.", "_imaps._tcp.", "_jabber-client._tcp.", "_jabber._tcp.", "_kerberos-adm._tcp.", "_kerberos._tcp.", "_kerberos._tcp.dc._msdcs.", "_kerberos._udp.", "_kpasswd._tcp.", "_kpasswd._udp.", "_ldap._tcp.", "_ldap._tcp.dc._msdcs.", "_ldap._tcp.gc._msdcs.", "_ldap._tcp.pdc._msdcs.", "_msdcs.", "_mysqlsrv._tcp.", "_ntp._udp.", "_pop3._tcp.", "_pop3s._tcp.", "_sip._tcp.", "_sip._tls.", "_sip._udp.", "_sipfederationtls._tcp.", "_sipinternaltls._tcp.", "_sips._tcp.", "_smtp._tcp.", "_ssh._tcp.", "_stun._tcp.", "_stun._udp.", "_tcp.", "_tls.", "_udp.", "_vlmcs._tcp.", "_vlmcs._udp.", "_wpad._tcp.", "_xmpp-client._tcp.", "_xmpp-server._tcp.", "_zip._tls"}},
}

type Response struct {
	RR  []dns.RR
	NS  string
	Rtt time.Duration
}

type Request struct {
	Qtype  uint16
	Query  string
	Domain string
}

type Config struct {
	JSON     *bool
	Debug    *bool
	QPS      *int
	resolver string
}

type Scan struct {
	*Config
	nsdataCache map[string][]structs.NSData
}

func New(cfg *Config, resolver string) *Scan {
	s := &Scan{
		Config:      cfg,
		nsdataCache: make(map[string][]structs.NSData),
	}
	if *cfg.Debug {
		log.Level = logrus.DebugLevel
	}
	s.Config.resolver = resolver
	return s
}

func (s *Scan) zoneTransfer(domain, server string) []string {
	var records []string
	t := new(dns.Transfer)
	req := prepMsg()
	req.Question[0] = dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  dns.TypeAXFR,
		Qclass: dns.ClassINET,
	}
	q, err := t.In(req, net.JoinHostPort(server, "53"))
	if err != nil {
		return records
		//	fmt.Println("error", err)
	}
	for res := range q {
		if res.Error != nil {
			break
		}
		for _, rr := range res.RR {
			records = append(records, rr.String())
		}
	}
	sort.Strings(records)
	return records
}

func (s *Scan) GetNSInfo(domain, name string, IP net.IP) (structs.NSInfo, error) {
	var newnsinfo structs.NSInfo
	info, _ := ipinfo(IP)
	newnsinfo.IPInfo = info
	newnsinfo.Name = name

	soa, rtt, err := QueryRRset(domain, dns.TypeSOA, IP.String(), false)
	if err == nil {
		newnsinfo.Rtt = rtt
		newnsinfo.Serial = int64(soa[0].(*dns.SOA).Serial)
	}

	keys, _, _ := QueryRRset(domain, dns.TypeDNSKEY, IP.String(), true)
	res, err := Query(domain, dns.TypeNS, IP.String(), true)
	if err == nil {
		valid, keyinfo, _ := s.ValidateRRSIG(keys, res.Msg.Answer)
		newnsinfo.DNSSECInfo = structs.DNSSECInfo{Valid: valid, KeyInfo: keyinfo, ChainValid: false}
		if keyinfo.Start == 0 && len(keys) == 0 {
			newnsinfo.Disabled = true
		}
	}
	newnsinfo.Msg = res.Msg
	return newnsinfo, nil
}

func (s *Scan) DomainScan(domain string) []Response {
	return s.domainscan(domain)
}

func (s *Scan) doZoneTransfer(domain string, ips []net.IP) ([]Response, error) {
	for _, ip := range ips {
		res := s.zoneTransfer(domain, ip.String())
		if len(res) > 0 {
			zt := ""
			for _, rr := range res {
				zt += fmt.Sprintln(rr)
			}
			if !*s.JSON {
				fmt.Println(zt)
			}
			// only print one. Further scanning not needed
			return []Response{}, nil
			// TODO compare hashes
			//	fmt.Printf("%x\n", Hash("key", []byte(zt)))
		} else if !*s.JSON {
			fmt.Printf("%s ", ip.String())
		}
	}
	return nil, fmt.Errorf("AXFR denied")
}

/*
func (s *Scan) calcAvgRtt(domain string, ips []net.IP) time.Duration {
	var avgRtt time.Duration
	avgRttServers := 0
	for _, ip := range ips {
		_, rtt, err := queryRRset(domain, dns.TypeSOA, ip.String(), false)
		if err != nil {
			continue
		}
		avgRtt += rtt
		avgRttServers++
	}
	avgRtt /= time.Duration(avgRttServers)
	return avgRtt
}
*/

func (s *Scan) bruteWorker(c chan Request, ns net.IP, respc chan Response) {
	//limiter := time.Tick(time.Millisecond * time.Duration(1000/(*s.QPS)))
	ticker := time.NewTicker(time.Millisecond * time.Duration(1000/(*s.QPS)))
	limiter := ticker.C
	for request := range c {
		var rrs []dns.RR
		<-limiter
		qtype := request.Qtype
		entry := request.Query
		domain := request.Domain
		if qtype == dns.TypeA {
			res, err := query(dns.Fqdn(entry+domain), dns.TypeA, ns.String(), true)
			if err != nil {
			} else {
				rrs = extractRR(res.Msg.Answer, dns.TypeA, dns.TypeCNAME)
			}
			log.Debugf("answered A for %s from %s: %#v %#v", entry+domain, ns.String(), rrs, res.Rtt)
			res2, rtt, _ := queryRRset(dns.Fqdn(entry+domain), dns.TypeAAAA, ns.String(), true)
			log.Debugf("answered AAAA for %s from %s: %#v %#v", entry+domain, ns.String(), res2, rtt)
			rrs = append(rrs, res2...)
			respc <- Response{RR: rrs, NS: ns.String(), Rtt: rtt}
			continue
		}
		res, rtt, _ := queryRRset(dns.Fqdn(entry+domain), qtype, ns.String(), true)
		log.Debugf("answered qtype %v for %s from %s: %#v", qtype, entry+domain, ns.String(), res)
		respc <- Response{RR: res, NS: ns.String(), Rtt: rtt}
	}
}

func (s *Scan) handleBruteResponses(scanEntries int, wildcardip, strResponses []string, respc chan Response) []Response {
	var responses []Response
	i := 0
	for resp := range respc {
		if len(resp.RR) > 0 {
			log.Debugf("got valid answer %v of %v: %#v", i, scanEntries-1, resp)
			resp.RR = removeWild(wildcardip, resp.RR)
			responses = append(responses, resp)
		}
		if i == scanEntries-1 {
			break
		}
		i++
	}

	for _, resp := range responses {
		if len(resp.RR) > 0 {
			for _, rr := range resp.RR {
				strResponses = append(strResponses, rr.String())
			}
		}
	}
	if !*s.JSON {
		sort.Strings(strResponses)
		for _, response := range strResponses {
			fmt.Println(response)
		}
	}
	return responses
}

func (s *Scan) FindNSIP(domain string) []net.IP {
	var ips []net.IP
	servers, _ := s.FindNS(dns.Fqdn(domain))
	for _, server := range servers {
		for _, info := range server.Info {
			ips = append(ips, info.IP)
		}
	}
	return ips
}

func (s *Scan) domainscan(domain string) []Response {
	var strResponses []string
	respc := make(chan Response, 100)

	ips := s.FindNSIP(domain)
	*s.QPS *= len(ips)

	scanEntries := 0
	for _, src := range DSP {
		scanEntries += len(src.Entries)
	}

	res, err := s.doZoneTransfer(domain, ips)
	if err == nil {
		return res
	}
	if !*s.JSON {
		fmt.Println(err)
	}

	t := time.Now()

	wildcardip := []string{}
	if !*s.JSON {
		res, _, _ := queryRRset(dns.Fqdn("*."+domain), dns.TypeA, ips[0].String(), true)
		if len(res) != 0 {
			for _, rr := range res {
				wildcardip = append(wildcardip, rr.(*dns.A).A.String())
				strResponses = append(strResponses, rr.String())
			}
		}
	}

	// setup a worker foreach nameserver
	var nsc []chan Request
	for _, ip := range ips {
		//for _, server := range servers {
		c := make(chan Request, scanEntries)
		nsc = append(nsc, c)
		go s.bruteWorker(c, ip, respc)
	}

	i := -1
	// send a scan request to the workers
	for _, src := range DSP {
		for _, entry := range src.Entries {
			i++
			q := Request{src.Qtype, entry, domain}
			nsc[i%len(ips)] <- q
		}
	}

	responses := s.handleBruteResponses(scanEntries, wildcardip, strResponses, respc)

	if !*s.JSON {
		fmt.Printf("\nScan took %s\n", time.Since(t))
	}
	return responses
}

func (s *Scan) Resolver() string {
	return s.resolver
}

func (s *Scan) NSData() map[string][]structs.NSData {
	return s.nsdataCache
}

func Query(q string, qtype uint16, server string, sec bool) (structs.Response, error) {
	return query(q, qtype, server, sec)
}

func QueryRRset(q string, qtype uint16, server string, sec bool) ([]dns.RR, time.Duration, error) {
	return queryRRset(q, qtype, server, sec)
}
