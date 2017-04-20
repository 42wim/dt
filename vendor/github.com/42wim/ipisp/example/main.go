package main

import (
	"fmt"
	"log"
	"net"

	"github.com/42wim/ipisp"
)

func main() {
	client, err := ipisp.NewDNSClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.LookupIP(net.ParseIP("4.2.2.2"))
	if err != nil {
		log.Fatalf("Error looking up 4.2.2.2: %v", err)
	}
	fmt.Printf("Resolved IP 4.2.2.2: %+v\n", resp)

	resp, err = client.LookupASN(ipisp.ASN(666))
	if err != nil {
		log.Fatalf("Failed to lookup ASN 666: %v", err)
	}
	fmt.Printf("Resolved ASN 666: %+v\n", resp)
}
