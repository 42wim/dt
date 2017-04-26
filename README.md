# dt 

DNS tool that displays information about your domain.

Very much a WIP. 
Caveats for now: DNSSEC only ZSK tests, uses 8.8.8.8 for initial domain lookup

# Installing

## Binaries
Binaries can be found [here] (https://github.com/42wim/dt/releases/)

## Building
Go 1.6.3+ is required. Make sure you have [Go](https://golang.org/doc/install) properly installed, including setting up your [GOPATH] (https://golang.org/doc/code.html#GOPATH)

```
cd $GOPATH
go get github.com/42wim/dt
```

You should now have matterbridge binary in the bin directory:

```
$ ls bin/
dt
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
```

![](https://gifyu.com/images/testda815.gif)
