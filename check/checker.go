package check

import (
	"fmt"
	"strings"
	"time"

	"github.com/42wim/dt/scan"
	"github.com/42wim/dt/structs"
	"github.com/miekg/dns"
)

type Checker interface {
	Scan(string)
	CreateReport(string) Report
}

type Report struct {
	Type   string
	Result []ReportResult
}

type ReportResult struct {
	Result  string
	Status  bool
	Error   string
	Records []string
	Name    string
}

type DomainReport struct {
	Name      string
	NSInfo    []structs.NSInfo
	Timestamp time.Time
	Report    []Report
	Scan      []scan.Response
}

func (r *Report) scanError(check, ns, ip, domain string, results []dns.RR, err error) bool {
	fail := false
	if err != nil {
		if !strings.Contains(err.Error(), "NXDOMAIN") && !strings.Contains(err.Error(), "no rr for") {
			r.Result = append(r.Result, ReportResult{Result: fmt.Sprintf("ERR : %s failed on %s (%s) for domain (%s): %s", check, ns, ip, domain, err)})
		}
		fail = true
	}
	if len(results) == 0 && err == nil {
		//              r.Result = append(r.Result, ReportResult{Result: fmt.Sprintf("ERR : %s failed on %s (%s): %s", check, ns, ip, "no records found")})
		fail = true
	}
	return fail
}
