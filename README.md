# dt 

DNS tool that displays information about your domain.

# Features
* common records scanning (use -scan)
* validate DNSSEC chain (use -debug to see more info)
* change query speed for scanning (default 10 queries per second)
* diagnostic of your domain (similar to intodns.com, dnsspy.io)
* For implemented checks see [#1](https://github.com/42wim/dt/issues/1)

Feedback, issues and PR's are welcome.

# TODO
* daemon mode
* grading 
* keeping history

# Installing

## Binaries
Binaries can be found [here](https://github.com/42wim/dt/releases/)

## Building
Go 1.6.3+ is required. Make sure you have [Go](https://golang.org/doc/install) properly installed, including setting up your [GOPATH] (https://golang.org/doc/code.html#GOPATH)

```
cd $GOPATH
go get github.com/42wim/dt
```

You should now have dt binary in the bin directory:

```
$ ls bin/
dt
```

# Usage
```
Usage:
        dt [FLAGS] domain

Example:
        dt icann.org
        dt -debug ripe.net
        dt -debug -scan yourdomain.com

Flags:
  -debug
        enable debug
  -json
        output in JSON
  -qps int
        queries per seconds (per nameserver) (default 10)
  -resolver string
        use this resolver for initial domain lookup (default "8.8.8.8")
  -scan
        scan domain for common records
  -showfail
        only show checks that fail or warn
```

# Running
```
./dt ripe.net
NS                      |IP                     |LOC |ASN        |ISP                                      |rtt          |Serial     |DNSSEC |ValidFrom    |ValidUntil
a3.verisigndns.com.     |69.36.145.33           |US  |ASN 36617  |AGTLD - VeriSign Global Registry Service |6.312503ms   |1492613104 |valid   |10 hours ago |4 weeks from now
                        |2001:502:cbe4::33      |US  |ASN 36622  |IGTLD - VeriSign Global Registry Service |12.844157ms  |1492613104 |valid   |10 hours ago |4 weeks from now
a1.verisigndns.com.     |209.112.113.33         |US  |ASN 36617  |AGTLD - VeriSign Global Registry Service |8.993407ms   |1492613104 |valid   |10 hours ago |4 weeks from now
                        |2001:500:7967::2:33    |US  |ASN 36622  |IGTLD - VeriSign Global Registry Service |12.03051ms   |1492613104 |valid   |10 hours ago |4 weeks from now
a2.verisigndns.com.     |209.112.114.33         |US  |ASN 36619  |CGTLD - VeriSign Global Registry Service |103.03539ms  |1492613104 |valid   |10 hours ago |4 weeks from now
                        |2620:74:19::33         |US  |ASN 36619  |CGTLD - VeriSign Global Registry Service |104.154197ms |1492613104 |valid   |10 hours ago |4 weeks from now
sns-pb.isc.org.         |192.5.4.1              |US  |ASN 3557   |ISC-AS - Internet Systems Consortium, In |5.563089ms   |1492613104 |valid   |10 hours ago |4 weeks from now
                        |2001:500:2e::1         |US  |ASN 3557   |ISC-AS - Internet Systems Consortium, In |11.509454ms  |1492613104 |valid   |10 hours ago |4 weeks from now
sec3.apnic.net.         |202.12.28.140          |AU  |ASN 4777   |APNIC-NSPIXP2-AS Asia Pacific Network In |253.352975ms |1492613104 |valid   |10 hours ago |4 weeks from now
                        |2001:dc0:1:0:4777::140 |AU  |ASN 4777   |APNIC-NSPIXP2-AS Asia Pacific Network In |266.28428ms  |1492613104 |valid   |10 hours ago |4 weeks from now
manus.authdns.ripe.net. |193.0.9.7              |NL  |ASN 197000 |RIPE-NCC-AUTHDNS-AS Reseaux IP Europeens |5.493287ms   |1492613104 |valid   |10 hours ago |4 weeks from now
                        |2001:67c:e0::7         |NL  |ASN 197000 |RIPE-NCC-AUTHDNS-AS Reseaux IP Europeens |11.403502ms  |1492613104 |valid   |10 hours ago |4 weeks from now
tinnie.arin.net.        |199.212.0.53           |US  |ASN 393225 |ARIN-PFS-IAD - ARIN Operations, US       |94.890834ms  |1492613104 |valid   |10 hours ago |4 weeks from now
                        |2001:500:13::c7d4:35   |US  |ASN 53535  |ARIN-PFS-ANYCAST - ARIN Operations, US   |96.854587ms  |1492613104 |valid   |10 hours ago |4 weeks from now
DNSSEC
         OK: DNSKEY validated. Chain validated
NS
         OK  : NS of all nameservers are identical
         OK  : Multiple nameservers found
         OK  : Your nameservers are in different subnets.
         OK  : Nameservers are spread over multiple AS
         OK  : IPv4 and IPv6 nameservers found.
         OK  : All nameservers are authoritative.
         OK  : All nameservers report they are not allowing recursive queries.
         OK  : Your nameservers are also listed as NS at the parent nameservers
         OK  : Your parent nameservers are also listed as NS at your nameservers
         OK  : No CNAMEs found for your NS records
GLUE
         WARN: no glue records found for [2001:500:2e::1 192.5.4.1] in NS of parent net.
         WARN: no glue records found for [2620:74:19::33 2001:500:2e::1 199.212.0.53 2001:502:cbe4::33 2001:dc0:1:0:4777::140 209.112.113.33 69.36.145.33 202.12.28.140 2001:500:7967::2:33 $09.112.114.33 192.5.4.1 2001:500:13::c7d4:35] in NS of ripe.net.
SOA
         OK  : SOA of all nameservers are identical
         WARN: Serial is not in the recommended format of YYYYMMDDnn.
         OK  : MNAME manus.authdns.ripe.net. is listed at the parent servers.
         OK  : Your nameservers have public / routable addresses.
MX
         OK  : MX of all nameservers are identical
         OK  : Multiple MX records found
         OK  : Your MX records have public / routable addresses.
         OK  : Your MX records resolve to different ips.
         OK  : No CNAMEs found for your MX records
         OK  : All MX records have reverse PTR records
Web
         OK  : Found a www record
         OK  : Found a root record
         OK  : Didn't find a CNAME for the root record
         OK  : Your www record has a public / routable address.
Spam
         WARN: No DMARC records found. Along with DKIM and SPF, DMARC helps prevent spam from your domain.
         WARN: No SPF records found. Along with DKIM and DMARC, SPF helps prevent spam from your domain.
```

```
./dt -debug ripe.net
DEBU[0000] validating ripe.net.
DEBU[0000] Asking NS (69.36.145.33) DNSKEY of ripe.net.
DEBU[0000] Trying validation RRSIG with DNSKEY AwEAAYXio3PIYXe4PqLmPGgemH52ZvUIDSdx+HkyoJW6SKuh82UFguzGh0xlbz5Dm5KenD2GG229/lSmU/+NvYeC+AFFB11dcoGr/5EZfb3kn+T+oaPbDyk6+tOcGJm8zHFVEP6lHi/hee5IbLQlngFpG5sf702/z5z/rQbm4OkuGPIz (flag 256, keytag 35431)
DEBU[0000] Validation failed
DEBU[0000] Trying validation RRSIG with DNSKEY AwEAAdYl56Gx3At/GI42bu2RmeQYWp3Y3WzjzYnM2h9c/twCjNa2bJPeIw2F9q+rOZhPugCn0+8X99XEmmJBvdBzaLTAZ3UsxXD1hKo1gwlpA0UUkJsUcgx51gqREEzEgUOLSB0oIwSopPpVOZRb9nfv2oNV1TvfXvAGmXLY+BnewBY5296Q/sEk8LhlkRAQuR1x25fjwxdyR+d2GC9+bjH+rXU54bOplRtTr7wCXMVV8CRkEaPRAuJpRNtUAX/IqpS3+A07BXPMHbvZAckmT1tuLNh4TG5auxxJ6a2ERj71FH7fbQODKuIWEL8oZgQB6Y3vevAUKAwjqjJsdGHt2oCpqn8= (flag 257, keytag 29740)
DEBU[0000] Validation succeeded
DEBU[0000] RRSIG validated (2017-04-29 11:02:59 +0200 CEST -> 2017-05-29 12:02:59 +0200 CEST)
DEBU[0000] Finding NS of parent: net.
DEBU[0000] Asking parent 192.43.172.30 (net.) DS of ripe.net.
DEBU[0000] parent DS digest: 570004384bf50cf787714ceb9e73de912d48cfc0e5c637785772d84bb50f85ae (keytag 29740)
DEBU[0000] child DS digest 570004384bf50cf787714ceb9e73de912d48cfc0e5c637785772d84bb50f85ae (keytag 29740)
DEBU[0000] ripe.net. validated

DEBU[0000] validating net.
DEBU[0000] Asking NS (192.26.92.30) DNSKEY of net.
DEBU[0000] Trying validation RRSIG with DNSKEY AQOYBnzqWXIEj6mlgXg4LWC0HP2n8eK8XqgHlmJ/69iuIHsa1TrHDG6TcOra/pyeGKwH0nKZhTmXSuUFGh9BCNiwVDuyyb6OBGy2Nte9Kr8NwWg4q+zhSoOf4D+gC9dEzg0yFdwT0DKEvmNPt0K4jbQDS4Yimb+uPKuF6yieWWrPYYCrv8C9KC8JMze2uT6NuWBfsl2fDUoV4l65qMww06D7n+p7RbdwWkAZ0fA63mXVXBZF6kpDtsYD7SUB9jhhfLQE/r85bvg3FaSs5Wi2BaqN06SzGWI1DHu7axthIOeHwg00zxlhTpoYCH0ldoQz+S65zWYi/fRJiyLSBb6JZOvn (flag 257, keytag 35886)
DEBU[0000] Validation succeeded
DEBU[0000] RRSIG validated (2017-04-20 18:33:57 +0200 CEST -> 2017-05-05 18:38:57 +0200 CEST)
DEBU[0000] Finding NS of parent: .
DEBU[0001] Asking parent 192.58.128.30 (.) DS of net.
DEBU[0001] parent DS digest: 7862b27f5f516ebe19680444d4ce5e762981931842c465f00236401d8bd973ee (keytag 35886)
DEBU[0001] child DS digest 7862b27f5f516ebe19680444d4ce5e762981931842c465f00236401d8bd973ee (keytag 35886)
DEBU[0001] net. validated

NS                      |IP                     |LOC |ASN        |ISP                                      |rtt          |Serial     |DNSSEC |ValidFrom    |ValidUntil
manus.authdns.ripe.net. |193.0.9.7              |NL  |ASN 197000 |RIPE-NCC-AUTHDNS-AS Reseaux IP Europeens |4.909712ms   |1493390344 |valid  |12 hours ago |4 weeks from now
                        |2001:67c:e0::7         |NL  |ASN 197000 |RIPE-NCC-AUTHDNS-AS Reseaux IP Europeens |11.205698ms  |1493390344 |valid  |12 hours ago |4 weeks from now
sns-pb.isc.org.         |192.5.4.1              |US  |ASN 3557   |ISC-AS - Internet Systems Consortium, In |4.502391ms   |1493390344 |valid  |12 hours ago |4 weeks from now
                        |2001:500:2e::1         |US  |ASN 3557   |ISC-AS - Internet Systems Consortium, In |11.525774ms  |1493390344 |valid  |12 hours ago |4 weeks from now
a3.verisigndns.com.     |69.36.145.33           |US  |ASN 36617  |AGTLD - VeriSign Global Registry Service |5.308344ms   |1493390344 |valid  |12 hours ago |4 weeks from now
                        |2001:502:cbe4::33      |US  |ASN 36623  |HGTLD - VeriSign Global Registry Service |12.050853ms  |1493390344 |valid  |12 hours ago |4 weeks from now
a1.verisigndns.com.     |209.112.113.33         |US  |ASN 26134  |BROAD-RUN-BORDER-AS - VeriSign Infrastru |5.11017ms    |1493390344 |valid  |12 hours ago |4 weeks from now
                        |2001:500:7967::2:33    |US  |ASN 36625  |KGTLD - VeriSign Global Registry Service |12.374661ms  |1493390344 |valid  |12 hours ago |4 weeks from now
a2.verisigndns.com.     |209.112.114.33         |US  |ASN 36619  |CGTLD - VeriSign Global Registry Service |10.563235ms  |1493390344 |valid  |12 hours ago |4 weeks from now
                        |2620:74:19::33         |US  |ASN 36625  |KGTLD - VeriSign Global Registry Service |16.876504ms  |1493390344 |valid  |12 hours ago |4 weeks from now
tinnie.arin.net.        |199.212.0.53           |US  |ASN 393225 |ARIN-PFS-IAD - ARIN Operations, US       |84.877944ms  |1493390344 |valid  |12 hours ago |4 weeks from now
                        |2001:500:13::c7d4:35   |US  |ASN 53535  |ARIN-PFS-ANYCAST - ARIN Operations, US   |83.173795ms  |1493390344 |valid  |12 hours ago |4 weeks from now
sec3.apnic.net.         |202.12.28.140          |AU  |ASN 4777   |APNIC-NSPIXP2-AS Asia Pacific Network In |257.939304ms |1493390344 |valid  |12 hours ago |4 weeks from now
                        |2001:dc0:1:0:4777::140 |AU  |ASN 4777   |APNIC-NSPIXP2-AS Asia Pacific Network In |258.446349ms |1493390344 |valid  |12 hours ago |4 weeks from now
```

![](https://gifyu.com/images/testda815.gif)
