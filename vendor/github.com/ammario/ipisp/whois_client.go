// Package ipisp provides a wrapper to team-cymru.com's IP to ASN service.
package ipisp

import (
	"bufio"
	"bytes"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var ncEOL = []byte("\r\n")

// Timeout is the TCP connection timeout
var Timeout = time.Second * 10

// Common errors
var (
	ErrUnexpectedTokens = errors.New("Unexpected tokens while reading Cymru response.")
)

const (
	netcatIPTokensLength  = 7
	netcatASNTokensLength = 5
)

// Service address
const (
	cymruNetcatAddress = "whois.cymru.com:43"
)

// whoisClient uses the whois client
type whoisClient struct {
	Conn net.Conn
	w    *bufio.Writer
	sc   *bufio.Scanner
	ncmu *sync.Mutex
}

// NewWhoisClient returns a connected WHOIS client.
// This client should be used for bulk lookups.
func NewWhoisClient() (Client, error) {
	var err error

	client := &whoisClient{}
	client.Conn, err = net.DialTimeout("tcp", cymruNetcatAddress, Timeout)
	client.ncmu = &sync.Mutex{}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	client.w = bufio.NewWriter(client.Conn)
	client.sc = bufio.NewScanner(client.Conn)

	client.Conn.SetDeadline(time.Now().Add(time.Second * 15))

	client.w.Write([]byte("begin"))
	client.w.Write(ncEOL)
	client.w.Write([]byte("verbose"))
	client.w.Write(ncEOL)

	err = client.w.Flush()
	if err != nil {
		return client, errors.Wrap(err, "failed to write to client")
	}

	// Discard first hello line
	client.sc.Scan()
	client.sc.Bytes()
	return client, errors.Wrap(client.sc.Err(), "failed to read from scanner")
}

// Close closes the client.
func (c *whoisClient) Close() error {
	c.Conn.SetWriteDeadline(time.Now().Add(time.Second))

	c.w.Write([]byte("end"))
	c.w.Write(ncEOL)
	// This error is not important, because the previous are a courtesy.
	c.w.Flush()
	return c.Conn.Close()
}

func (c *whoisClient) LookupIPs(ips []net.IP) (resp []Response, err error) {
	resp = make([]Response, 0, len(ips))

	c.ncmu.Lock()
	defer c.ncmu.Unlock()

	for _, ip := range ips {
		c.w.WriteString(ip.String())
		c.w.Write(ncEOL)
		if err = c.w.Flush(); err != nil {
			return resp, err
		}
	}

	c.Conn.SetDeadline(time.Now().Add(time.Second*5 + (time.Second * time.Duration(len(ips)))))

	// Raw response
	var raw []byte
	var tokens [][]byte

	var finished bool

	// Read results
	for !finished && c.sc.Scan() {

		raw = c.sc.Bytes()
		if bytes.HasPrefix(raw, []byte("Error: ")) {
			return resp, errors.New(string(bytes.TrimSpace(bytes.TrimLeft(raw, "Error: "))))
		}
		tokens = bytes.Split(raw, []byte{'|'})

		if len(tokens) != netcatIPTokensLength {
			return resp, ErrUnexpectedTokens
		}

		// Trim excess whitespace from tokens
		for i := range tokens {
			tokens[i] = bytes.TrimSpace(tokens[i])
		}

		re := Response{}

		// Read ASN
		asnList := string(tokens[0])

		var asns []ASN
		asns, err = parseASNs(asnList)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse asn list %v", asnList)
		}
		re.ASN = asns[0]

		// Read IP
		re.IP = net.ParseIP(string(tokens[1]))

		// Read range
		bgpPrefix := string(tokens[2])
		// Account for 'NA' BGP Prefix responses from the API
		// More info: https://github.com/ammario/ipisp/issues/13
		if bgpPrefix == "NA" {
			bgpPrefix = re.IP.String() + "/32"
		}

		if _, re.Range, err = net.ParseCIDR(bgpPrefix); err != nil {
			return
		}

		// Read country
		re.Country = string(bytes.TrimSpace(tokens[3]))

		// Read registry
		re.Registry = string(bytes.ToUpper(tokens[4]))

		// Read allocated. Ignore error as a lot of entries don't have an allocated value.
		re.AllocatedAt, _ = time.Parse("2006-01-02", string(tokens[5]))

		// Read name
		re.Name = ParseName(string(tokens[6]))

		// Add to response slice
		resp = append(resp, re)
		if len(resp) == cap(resp) {
			finished = true
		}
	}
	return resp, err
}

// LookupIP is a single IP convenience proxy of LookupIPs
func (c *whoisClient) LookupIP(ip net.IP) (*Response, error) {
	resp, err := c.LookupIPs([]net.IP{ip})
	if len(resp) == 0 {
		return nil, err
	}
	return &resp[0], err
}

// LookupASNs looks up ASNs. Response IP and Range fields are zeroed
func (c *whoisClient) LookupASNs(asns []ASN) (resp []Response, err error) {
	resp = make([]Response, 0, len(asns))

	c.ncmu.Lock()
	defer c.ncmu.Unlock()
	for _, asn := range asns {
		c.w.WriteString(asn.String())
		c.w.Write(ncEOL)
		if err = c.w.Flush(); err != nil {
			return resp, err
		}
	}

	c.Conn.SetDeadline(time.Now().Add(time.Second*5 + (time.Second * time.Duration(len(asns)))))

	// Raw response
	var raw []byte
	var tokens [][]byte
	var asn int

	var finished bool

	// Read results
	for !finished && c.sc.Scan() {
		raw = c.sc.Bytes()
		if bytes.HasPrefix(raw, []byte("Error: ")) {
			return resp, errors.Errorf("recieved err: %v", raw)
		}
		tokens = bytes.Split(raw, []byte{'|'})

		if len(tokens) != netcatASNTokensLength {
			return resp, ErrUnexpectedTokens
		}

		// Trim excess whitespace from tokens
		for i := range tokens {
			tokens[i] = bytes.TrimSpace(tokens[i])
		}

		re := Response{}

		// Read ASN
		if asn, err = strconv.Atoi(string(tokens[0])); err != nil {
			return nil, errors.Wrapf(err, "failed to atoi %s", tokens[0])
		}
		re.ASN = ASN(asn)
		// Read country
		re.Country = string(tokens[1])
		// Read registry
		re.Registry = string(bytes.ToUpper(tokens[2]))
		// Read allocated. Ignore error as a lot of entries don't have an allocated value.
		re.AllocatedAt, _ = time.Parse("2006-01-02", string(tokens[3]))
		// Read name
		re.Name = ParseName(string(tokens[4]))

		// Add to response slice
		resp = append(resp, re)
		if len(resp) == cap(resp) {
			finished = true
		}
	}
	return resp, err
}

// LookupASN is a single ASN convenience proxy of LookupASNs
func (c *whoisClient) LookupASN(asn ASN) (*Response, error) {
	resp, err := c.LookupASNs([]ASN{asn})
	return &resp[0], err
}
