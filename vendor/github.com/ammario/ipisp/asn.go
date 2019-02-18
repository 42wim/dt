package ipisp

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// ASN represents an Autonomous Systems Number.
// See https://en.wikipedia.org/wiki/Autonomous_system_(Internet).
type ASN int

// ParseASN parses a string like `AS2341` into ASN `2341`.
func ParseASN(asn string) (ASN, error) {
	// A special value from the API.
	// More info: https://github.com/ammario/ipisp/issues/10.
	if asn == "NA" {
		return 0, nil
	}
	// Make case insensitive
	asn = strings.ToUpper(asn)
	if len(asn) > 2 && asn[:2] == "AS" {
		asn = asn[2:]
	}

	nn, err := strconv.Atoi(asn)
	return ASN(nn), errors.Wrap(err, "failed to conv into to string")
}


// String represents an ASN like `5544`` as `AS5544`.`
func (a ASN) String() string {
	if a == 0 {
		return "N/A"
	}
	return "AS" + strconv.Itoa(int(a))
}
