package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "lo"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
	// layer options
	srcMac, dstMac net.HardwareAddr
	//srcIp, dstIp    net.IP
	srcPort, dstPort int
	count            int
)

type IPv4Range struct {
	sipStart net.IP
	dipStart net.IP
	sipEnd   net.IP
	dipEnd   net.IP
	sip      net.IP
	dip      net.IP
}

func (v IPv4Range) next() {
	for i := 0; i < 4; i++ {
		if v.sip[15-i] >= v.sipEnd[15-i] {
			v.sip[15-i] = v.sipStart[15-i]
		} else {
			v.sip[15-i]++
			return
		}
	}
	for i := 0; i < 4; i++ {
		if v.dip[15-i] >= v.dipEnd[15-i] {
			v.dip[15-i] = v.dipStart[15-i]
		} else {
			v.dip[15-i]++
			return
		}
	}
}

func main() {
	// command-line flags
	_device := flag.String("device", "lo", "device name")
	_count := flag.Int("count", 1, "repeat count")
	_srcMac := flag.String("smac", "02:00:00:00:00:01", "source MAC")
	_dstMac := flag.String("dmac", "06:00:00:00:00:01", "destination MAC")
	_srcIp := flag.String("sip", "127.0.0.3-2", "source IPv4 address range")
	_dstIp := flag.String("dip", "10.0.3-1.11", "destination IPv4 address range")
	_srcPort := flag.String("sport", "11-13", "source udp port range")
	_dstPort := flag.String("dport", "41-43", "destination udp port range")

	// parse and set command-line options
	flag.Parse()

	device = *_device
	count = *_count
	srcMac, _ = net.ParseMAC(*_srcMac)
	dstMac, _ = net.ParseMAC(*_dstMac)

	// simply doing "var ipv4range IPv4Range" would not set len of the slice.
	ipv4range := IPv4Range{
		sip:      net.ParseIP("0.0.0.0"),
		sipStart: net.ParseIP("0.0.0.0"),
		sipEnd:   net.ParseIP("0.0.0.0"),
		dip:      net.ParseIP("0.0.0.0"),
		dipStart: net.ParseIP("0.0.0.0"),
		dipEnd:   net.ParseIP("0.0.0.0"),
	}

	ipstart, ipend, err := parse_ipv4_range(*_srcIp)
	if err != nil {
		fmt.Println("Parse failed. _srcIp:", *_srcIp)
		log.Fatal(err) // exit with err
	}
	copy(ipv4range.sip, ipstart)
	copy(ipv4range.sipStart, ipstart)
	copy(ipv4range.sipEnd, ipend)

	ipstart, ipend, err = parse_ipv4_range(*_dstIp)
	if err != nil {
		fmt.Println("Parse failed. _dstIp:", *_srcIp)
		log.Fatal(err) // exit with err
	}
	copy(ipv4range.dip, ipstart)
	copy(ipv4range.dipStart, ipstart)
	copy(ipv4range.dipEnd, ipend)

	sportStart, sportEnd, err := parse_port_range(*_srcPort)
	if err != nil {
		fmt.Println("Parse failed. _srcPort:", *_srcPort)
		log.Fatal(err) // exit with err
	}
	dportStart, dportEnd, err := parse_port_range(*_dstPort)
	if err != nil {
		fmt.Println("Parse failed. _dstPort:", *_dstPort)
		log.Fatal(err) // will exit with err
	}

	// Set other options (false or true)
	options.FixLengths = true
	options.ComputeChecksums = true

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	rawBytes := make([]byte, 200)

	ipv4Layer := &layers.IPv4{
		Version:    4,   //uint8
		IHL:        5,   //uint8
		TOS:        0,   //uint8
		Id:         0,   //uint16
		Flags:      0,   //IPv4Flag
		FragOffset: 0,   //uint16
		TTL:        255, //uint8
		Protocol:   17,  //IPProtocol UDP(17)
		SrcIP:      net.ParseIP("0.0.0.0"),
		DstIP:      net.ParseIP("0.0.0.0"),
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: 0x800,
	}

	// send packets: Loop = { IP src { IP dst { L4 src { L4 dst } } } }
	sum := 1
	for {

		ipv4Layer.SrcIP = net.ParseIP(ipv4range.sip.String())
		ipv4Layer.DstIP = net.ParseIP(ipv4range.dip.String())

		for sport := sportStart; sport <= sportEnd; sport++ {
			udpLayer.SrcPort = layers.UDPPort(sport)

			for dport := dportStart; dport <= dportEnd; dport++ {
				udpLayer.DstPort = layers.UDPPort(dport)

				// Set layer used for UDP checksum calculation.
				udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
				// Actually send packet, and exit if <count> num of packets were sent.
				send_udp(rawBytes, udpLayer, ipv4Layer, ethernetLayer)
				sum += 1
				if sum > count {
					goto END_SENDPACKET
				}
				// when sending to lo, packet will be dropped without this.
				if device == "lo" {
					time.Sleep(1000 * time.Nanosecond)
				}
			}
		}
		ipv4range.next()
	}
END_SENDPACKET:
}

func send_udp(data []byte,
	udpLayer *layers.UDP,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		udpLayer,
		gopacket.Payload(data),
	)
	return send_ipv4(buffer.Bytes(), ipv4Layer, ethernetLayer)
}

func send_ipv4(data []byte,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer_ipv4 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ipv4, options,
		ipv4Layer,
		gopacket.Payload(data),
	)
	return send_ethernet(buffer_ipv4.Bytes(), ethernetLayer)
}

func send_ethernet(data []byte,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer_ethernet := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ethernet, options,
		ethernetLayer,
		gopacket.Payload(data),
	)
	err = handle.WritePacketData(buffer_ethernet.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	return err
}

func parse_port_range(port string) (portStart, portEnd int, err error) {
	var p0, p1 int

	if strings.Contains(port, "-") {
		fmt.Println("port:", port)
		ports := strings.Split(port, "-")
		if len(ports) != 2 {
			err = errors.New("port parse failed.")
			return
		}
		p0, err = strconv.Atoi(ports[0])
		if err != nil {
			return
		}
		p1, err = strconv.Atoi(ports[1])
		if err != nil {
			return
		}
		if p0 < p1 {
			portStart = p0
			portEnd = p1
		} else {
			portStart = p1
			portEnd = p0
		}
	} else {
		portStart, err = strconv.Atoi(port)
		if err != nil {
			return
		}
		portEnd = portStart
	}
	return
}

// ipstart, ipend, err := parse_ipv4_range(_srcIp)
func parse_ipv4_range(ipv4 string) (ipstart, ipend net.IP, err error) {
	var i0, i1 int
	ipstart = net.ParseIP("0.0.0.0")
	ipend = net.ParseIP("0.0.0.0")

	ip := strings.Split(ipv4, ".")
	if len(ip) != 4 {
		err = fmt.Errorf("Cannot parse IPv4 address range (.): %s", ipv4)
		return
	}
	for i := 0; i < 4; i++ {
		if strings.Contains(ip[i], "-") {
			s := strings.Split(ip[i], "-")
			if len(s) != 2 {
				err = fmt.Errorf("Cannot parse IPv4 address range (-): %s", ipv4)
			}
			i0, err = strconv.Atoi(s[0])
			if err != nil {
				return
			}
			a0 := byte(i0)
			i1, err = strconv.Atoi(s[1])
			if err != nil {
				return
			}
			a1 := byte(i1)
			if a0 < a1 {
				ipstart[12+i] = a0
				ipend[12+i] = a1
			} else {
				ipstart[12+i] = a1
				ipend[12+i] = a0
			}
		} else {
			i0, err = strconv.Atoi(ip[i])
			if err != nil {
				return
			}
			a0 := byte(i0)
			ipstart[12+i] = a0
			ipend[12+i] = a0
		}
	}
	return
}
