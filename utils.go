package main

import (
	"net"

	"github.com/42wim/dt/structs"
	"github.com/ammario/ipisp"
)

func ipinfo(ip net.IP) (structs.IPInfo, error) {
	client, _ := ipisp.NewDNSClient()
	resp, err := client.LookupIP(net.ParseIP(ip.String()))
	if err != nil {
		return structs.IPInfo{}, err
	}
	return structs.IPInfo{
		IP:  ip,
		Loc: resp.Country,
		ASN: resp.ASN,
		ISP: resp.Name.Raw,
	}, nil
}

func removeIPv6(nsdatas []structs.NSData) []structs.NSData {
	var newdatas []structs.NSData
	for _, nsdata := range nsdatas {
		var ips []net.IP
		var infos []structs.NSInfo
		for _, ip := range nsdata.IP {
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
		nsdata.IP = ips

		for _, info := range nsdata.Info {
			if info.IP.To4() != nil {
				infos = append(infos, info)
			}
		}
		nsdata.Info = infos

		newdatas = append(newdatas, nsdata)
	}
	return newdatas
}
