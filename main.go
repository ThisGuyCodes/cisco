package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"
)

type NAT struct {
	Proto             NATProto
	InsideGlobal      net.IP
	InsideGlobalPort  int
	InsideLocal       net.IP
	InsideLocalPort   int
	OutsideLocal      net.IP
	OutsideLocalPort  int
	OutsideGlobal     net.IP
	OutsideGlobalPort int
	Created           time.Time
	Used              time.Time
	Timeout           time.Duration
}

type NATS []*NAT

func (nats NATS) Where(fn func(*NAT) bool) NATS {
	filtered := make(NATS, 0)
	for _, nat := range nats {
		if fn(nat) {
			filtered = append(filtered, nat)
		}
	}
	return filtered
}

type NATProto uint8

func (nat NATProto) MarshalJSON() ([]byte, error) {
	return json.Marshal(NAT_NAMES[nat])
}

func (nat *NATProto) UnmarshalJSON(data []byte) error {
	var dest string
	err := json.Unmarshal(data, &dest)
	*nat = NAT_REVERSE_NAMES[dest]
	return err
}

const (
	UDP_NAT NATProto = iota
	TCP_NAT
	STATIC_NAT
	ICMP_NAT

	DATE_FORMAT = "01/02/06 15:04:05"
)

var (
	ROUTE_SEP    = []byte("\n\n")
	ROUTE_HEADER = []byte("Pro")

	ROUTE_REGEXP    = regexp.MustCompile(`^(-{3}|tcp|udp|icmp)\s+([\-\:0-9\.]+)\s+([\-\:0-9\.]+)\s+([\-\:0-9\.]+)\s+([\-\:0-9\.]+)$`)
	TIME_REGEXP     = regexp.MustCompile(`^\s+create:\s+([^,]+),\s+use:\s+([^,]+),\s+timeout:\s+([^,]+)$`)
	DURATION_REGEXP = regexp.MustCompile(`^(\d\d):(\d\d):(\d\d)$`)

	DURATION_REPLACE = []byte(`${1}h${2}m${3}s`)

	NAT_TRANSLATION = map[byte]NATProto{
		byte('u'): UDP_NAT,
		byte('t'): TCP_NAT,
		byte('-'): STATIC_NAT,
		byte('i'): ICMP_NAT,
	}

	NAT_NAMES = map[NATProto]string{
		UDP_NAT:    "udp",
		TCP_NAT:    "tcp",
		STATIC_NAT: "static",
		ICMP_NAT:   "icmp",
	}
	NAT_REVERSE_NAMES = reverseNATNames(NAT_NAMES)
)

func reverseNATNames(names map[NATProto]string) map[string]NATProto {
	reversed := make(map[string]NATProto, len(names))
	for key, value := range names {
		reversed[value] = key
	}
	return reversed
}

func routeSplitFunc(data []byte, atEOF bool) (int, []byte, error) {
	if len(data) == 0 && atEOF {
		return 0, nil, nil
	}
	from, to, advance := 0, 0, 0

	i := bytes.Index(data, ROUTE_SEP)
	if i == -1 {
		if !atEOF {
			// We don't have a whole route, request more data
			return 0, nil, nil
		} else {
			if bytes.HasSuffix(data, []byte("\n")) {
				// Ends in a newline at EOF, we're done
				return len(data), data[:len(data)-1], nil
			} else {
				return 0, nil, errors.New("Improperly formatted file: it must end with an empty line")
			}
		}
	} else {
		to = i
		// We want to omit the seperator
		advance = i + len(ROUTE_SEP)
	}

	if bytes.HasPrefix(data, ROUTE_HEADER) {
		// This includes the header, we need to omit it
		// Find the end of the header line, and omit the newline character
		from = bytes.Index(data, []byte("\n")) + 1
	}

	return advance, data[from:to], nil
}

func (nat *NAT) Parse(data []byte) error {
	var err error
	lines := bytes.SplitN(data, []byte("\n"), 3)
	ips := ROUTE_REGEXP.FindSubmatch(lines[0])

	nat.Proto = NAT_TRANSLATION[ips[1][0]]

	if nat.Proto == STATIC_NAT {
		nat.InsideGlobal = net.ParseIP(string(ips[2]))
		nat.InsideLocal = net.ParseIP(string(ips[3]))
		nat.OutsideLocal = net.ParseIP(string(ips[4]))
		nat.OutsideGlobal = net.ParseIP(string(ips[5]))
	} else {
		nat.InsideGlobal, nat.InsideGlobalPort, err = parseIpPort(ips[2], "Inside Global")
		if err != nil {
			return err
		}

		nat.InsideLocal, nat.InsideLocalPort, err = parseIpPort(ips[3], "Inside Local")
		if err != nil {
			return err
		}

		nat.OutsideLocal, nat.OutsideLocalPort, err = parseIpPort(ips[4], "Outside Local")
		if err != nil {
			return err
		}

		nat.OutsideGlobal, nat.OutsideGlobalPort, err = parseIpPort(ips[5], "Outside Global")
		if err != nil {
			return err
		}
	}

	times := TIME_REGEXP.FindSubmatch(lines[1])

	nat.Created, err = time.Parse(DATE_FORMAT, string(times[1]))
	if err != nil {
		return err
	}

	nat.Used, err = time.Parse(DATE_FORMAT, string(times[2]))
	if err != nil {
		return err
	}

	timeout := DURATION_REGEXP.ReplaceAll(times[3], DURATION_REPLACE)

	nat.Timeout, err = time.ParseDuration(string(timeout))
	return err
}

func parseIpPort(data []byte, name string) (net.IP, int, error) {
	host, port, err := net.SplitHostPort(string(data))
	if err != nil {
		errStr := fmt.Sprintf("Could not parse %s address: %s", name, err)
		return nil, 0, errors.New(errStr)
	}

	hostIp := net.ParseIP(host)
	hostPort, err := strconv.Atoi(port)

	if err != nil {
		errStr := fmt.Sprintf("Could not parse %s port: %s", name, err)
		return hostIp, 0, errors.New(errStr)
	}

	return hostIp, hostPort, nil
}

func main() {
	routeScanner := bufio.NewScanner(os.Stdin)
	routeScanner.Split(routeSplitFunc)

	fmt.Println("Getting data")
	var nats NATS
	for routeScanner.Scan() {
		nat := new(NAT)
		err := nat.Parse(routeScanner.Bytes())
		if err != nil {
			log.Fatalln(err)
		}
		nats = append(nats, nat)
	}
	fmt.Println("Data parsed, getting counts")

	long_time := 1 * time.Hour
	long_time_left := func(nat *NAT) bool { return nat.Timeout > long_time }

	nat_type := func(t NATProto) func(nat *NAT) bool {
		return func(nat *NAT) bool {
			return nat.Proto == t
		}
	}

	udp_nats := nats.Where(nat_type(UDP_NAT))
	tcp_nats := nats.Where(nat_type(TCP_NAT))
	icmp_nats := nats.Where(nat_type(ICMP_NAT))

	long_udp_nats := udp_nats.Where(long_time_left)
	long_tcp_nats := tcp_nats.Where(long_time_left)
	long_icmp_nats := icmp_nats.Where(long_time_left)

	var sum_udp_timeout time.Duration
	for _, nat := range udp_nats {
		sum_udp_timeout += nat.Timeout
	}

	var sum_tcp_timeout time.Duration
	for _, nat := range tcp_nats {
		sum_tcp_timeout += nat.Timeout
	}

	fmt.Printf("average udp timeout: %v\n", sum_udp_timeout/time.Duration(len(udp_nats)))
	fmt.Printf("average tcp timeout: %v\n", sum_tcp_timeout/time.Duration(len(tcp_nats)))

	fmt.Printf(`Counts:
udp: %[2]d | >%[1]v left: %[3]d (%[4]d%%)
tcp: %[5]d | >%[1]v left: %[6]d (%[7]d%%)
icmp: %[8]d | >%[1]v left: %[9]d (%[10]d%%)
`,
		long_time,
		len(udp_nats), len(long_udp_nats), len(long_udp_nats)*100/len(udp_nats),
		len(tcp_nats), len(long_tcp_nats), len(long_tcp_nats)*100/len(tcp_nats),
		len(icmp_nats), len(long_icmp_nats), len(long_icmp_nats)*100/len(icmp_nats))

}
