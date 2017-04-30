package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/briandowns/spinner"
	"github.com/miekg/dns"
)

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

type ScanResponse struct {
	RR  []dns.RR
	NS  string
	Rtt time.Duration
}

type ScanRequest struct {
	Qtype  uint16
	Query  string
	Domain string
}

func zoneTransfer(domain, server string) []string {
	var records []string
	t := new(dns.Transfer)
	req := prepMsg()
	req.Question[0] = dns.Question{dns.Fqdn(domain), dns.TypeAXFR, dns.ClassINET}
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

func domainscan(domain string) {
	var ips []net.IP
	respc := make(chan ScanResponse, 100)

	servers, _ := findNS(dns.Fqdn(domain))
	for _, server := range servers {
		for _, info := range server.Info {
			ips = append(ips, info.IP)
		}
	}
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)

	scanEntries := 0
	for _, src := range DSP {
		scanEntries = scanEntries + len(src.Entries)
	}

	*flagQPS = *flagQPS * len(servers)

	for _, ip := range ips {
		res := zoneTransfer(domain, ip.String())
		if len(res) > 0 {
			zt := ""
			for _, rr := range res {
				zt = zt + fmt.Sprintln(rr)
			}
			fmt.Println(zt)
			// only print one. Further scanning not needed
			return
			// TODO compare hashes
			//	fmt.Printf("%x\n", Hash("key", []byte(zt)))
		} else {
			fmt.Printf("%s ", ip.String())
		}
	}
	fmt.Println(": AXFR denied")

	s.Suffix = " Scanning... will take approx " + fmt.Sprintf("%#v seconds", scanEntries/(len(servers)*(*flagQPS)))
	s.Start()

	res, _, _ := queryRRset(dns.Fqdn("*."+domain), dns.TypeA, ips[0].String(), true)
	// TODO handle * record correctly
	if len(res) != 0 {
		s.Stop()
		fmt.Println()
		for _, rr := range res {
			fmt.Println(rr.String())
		}
		return
	}

	var nsc []chan ScanRequest
	for _, server := range servers {
		c := make(chan ScanRequest, 100)
		nsc = append(nsc, c)
		//fmt.Printf("scanning %s\n", server.IP[0])
		go func(c chan ScanRequest, ns net.IP) {
			limiter := time.Tick(time.Millisecond * time.Duration(1000/(*flagQPS)))
			for request := range c {
				var rrs []dns.RR
				<-limiter
				qtype := request.Qtype
				entry := request.Query
				domain := request.Domain
				if qtype == dns.TypeA {
					res, err := query(dns.Fqdn(entry+domain), dns.TypeA, ns.String(), true)
					if err != nil {
						//fmt.Println(err)
					} else {
						a := extractRR(res.Msg.Answer, dns.TypeA)
						cname := extractRR(res.Msg.Answer, dns.TypeCNAME)
						rrs = append(rrs, a...)
						rrs = append(rrs, cname...)
					}
					res2, rtt, err := queryRRset(dns.Fqdn(entry+domain), dns.TypeAAAA, ns.String(), true)
					if err != nil && len(res2) != 0 {
						//fmt.Println(err)
					}
					rrs = append(rrs, res2...)
					respc <- ScanResponse{RR: rrs, NS: ns.String(), Rtt: rtt}
					continue
				}
				res, rtt, err := queryRRset(dns.Fqdn(entry+domain), qtype, ns.String(), true)
				if err != nil && len(res) != 0 {
					//fmt.Println(err)
				}
				respc <- ScanResponse{RR: res, NS: ns.String(), Rtt: rtt}
			}
		}(c, server.Info[0].IP)
	}

	i := -1
	for _, src := range DSP {
		for _, entry := range src.Entries {
			i++
			q := ScanRequest{src.Qtype, entry, domain}
			nsc[i%len(servers)] <- q
		}
	}

	var responses []string
	i = 0
	for resp := range respc {
		if len(resp.RR) > 0 {
			for _, rr := range resp.RR {
				responses = append(responses, rr.String())
			}
		}
		if i == scanEntries-1 {
			break
		}
		i++
	}

	s.Stop()

	sort.Strings(responses)
	for _, response := range responses {
		fmt.Println(response)
	}
}

func Hash(tag string, data []byte) []byte {
	h := hmac.New(sha256.New, []byte(tag))
	h.Write(data)
	return h.Sum(nil)
}
