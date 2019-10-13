package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"text/tabwriter"
	"time"

	"github.com/42wim/dt/check"
	"github.com/42wim/dt/structs"
	"github.com/dustin/go-humanize"
)

func outputter(wc chan structs.NSInfo, done chan struct{}) {
	const padding = 1
	var w *tabwriter.Writer
	if *flagJSON {
		w = tabwriter.NewWriter(ioutil.Discard, 0, 0, padding, ' ', tabwriter.Debug)
	} else {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.Debug)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "NS\tIP\tLOC\tASN\tISP\trtt\tSerial\tDNSSEC\tValidFrom\tValidUntil\n")
	m := make(map[string][]structs.NSInfo)
	for input := range wc {
		m[input.Name] = append(m[input.Name], input)
	}
	for _, info := range m {
		i := 0
		var failed bool
		for _, ns := range info {
			if ns.Rtt == 0 {
				failed = true
			}
			// TODO output somewhere else
			// LAME servers
			auth := ""
			if ns.Msg != nil && !ns.Msg.Authoritative {
				auth = " L"
			}
			if failed {
				fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.Name, ns.IPInfo.IP.String()+auth, ns.Loc, ns.ASN, ns.ISP, "error", "error", "error")
				fmt.Fprintln(w)
				break
			}
			if ns.IPInfo.IP.To4() == nil {
				IPv6Guess = true
			}

			if i == 0 {
				fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.Name, ns.IPInfo.IP.String()+auth, ns.Loc, ns.ASN, fmt.Sprintf("%.40s", ns.ISP), ns.Rtt, ns.Serial)
			} else {
				fmt.Fprintf(w, "\t%v\t%v\t%v\t%v\t%v\t%v\t", ns.IPInfo.IP.String()+auth, ns.Loc, ns.ASN, fmt.Sprintf("%.40s", ns.ISP), ns.Rtt, ns.Serial)
			}
			//if ns.Valid && ns.ChainValid {
			if ns.Valid {
				fmt.Fprintf(w, "%v\t%s\t%s", "valid", humanize.Time(time.Unix(ns.KeyInfo.Start, 0)), humanize.Time(time.Unix(ns.KeyInfo.End, 0)))
			} else {
				if ns.DNSSECInfo.Disabled {
					fmt.Fprintf(w, "%v\t%s\t%s", "disabled", "", "")
				} else {
					fmt.Fprintf(w, "%v\t%s\t%s", "invalid", humanize.Time(time.Unix(ns.KeyInfo.Start, 0)), humanize.Time(time.Unix(ns.KeyInfo.End, 0)))
				}
			}
			i++
			fmt.Fprintln(w)
		}
	}
	w.Flush()
	done <- struct{}{}
}

func printDomainReport(domainReport check.DomainReport, flagShowFail bool) {
	fmt.Println()
	for _, report := range domainReport.Report {
		fmt.Print(report)
	}
	fmt.Println()

	if !flagShowFail {
		for _, report := range domainReport.Report {
			fmt.Println(report.Type)
			for _, res := range report.Result {
				if res.Result != "" {
					fmt.Println("\t", res.Result)
				}
			}
		}
	} else {
		for _, report := range domainReport.Report {
			for _, res := range report.Result {
				if res.Result != "" && !res.Status {
					fmt.Println(report.Type, "\t", res.Result)
				}
			}
		}
	}
}
