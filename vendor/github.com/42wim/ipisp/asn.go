package ipisp

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

//ASN contains an Autonomous Systems Number
type ASN int

//ParseASN parses a string like AS2341 into an ASN
func ParseASN(asn string) (ASN, error) {
	//Make case insensitive
	asn = strings.ToUpper(asn)
	a := strings.Fields(asn)
	if len(asn) > 2 {
		asn = a[0][2:]
		nn, err := strconv.Atoi(asn)
		return ASN(nn), errors.Wrap(err, "failed to conv into to string")
	}
	return 0, errors.Errorf("invalid asn")
}

//String implements fmt.Stringer
func (a ASN) String() string {
	return "AS" + strconv.Itoa(int(a))
}
