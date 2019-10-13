package main

import (
	"net"

	"github.com/42wim/dt/structs"
)

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
