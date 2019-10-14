package structs

import (
	"net"
	"time"

	"github.com/ammario/ipisp"
	"github.com/miekg/dns"
)

type NSInfo struct {
	Name   string
	Rtt    time.Duration
	Serial int64
	IPInfo
	DNSSECInfo
	Msg     *dns.Msg `json:"-"`
	Version string
}

type NSData struct {
	Name string
	Info []NSInfo
	IP   []net.IP
}

type IPInfo struct {
	IP  net.IP
	Loc string
	ASN ipisp.ASN
	ISP string
}

type DNSSECInfo struct {
	Valid      bool
	ChainValid bool
	Disabled   bool
	KeyInfo
}

type KeyInfo struct {
	Start int64
	End   int64
}

type Response struct {
	Msg    *dns.Msg
	Server string
	Rtt    time.Duration
}
