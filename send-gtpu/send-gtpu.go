package main

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "net"
    "time"
    "flag"
    "fmt"
    "strings"
    "strconv"
    "errors"
)

var (
    //device       string = "enp8s0f1" // i40e
    device          string = "lo"
    snapshot_len    int32  = 1024
    promiscuous     bool   = false
    err             error
    timeout         time.Duration = 30 * time.Second
    handle          *pcap.Handle
    buffer          gopacket.SerializeBuffer
    options         gopacket.SerializeOptions
    // layer options
    srcMac, dstMac  net.HardwareAddr
    srcIp, dstIp    net.IP
    srcPort, dstPort    int
    count           int
)

func main() {
    // Set other options (false or true)
    options.FixLengths = true
    // TODO: Packet malformed when ComputeChecksum is true !?
    //options.ComputeChecksums = true

    // command-line flags
    _dev     := flag.String("dev", "lo", "repeat count")
    _count   := flag.Int("count", 1, "repeat count")
    _srcMac  := flag.String("smac", "02:00:00:00:00:01", "source MAC")
    _dstMac  := flag.String("dmac", "06:00:00:00:00:01", "destination MAC")
    _srcIp   := flag.String("sip", "127.0.0.2", "source IPv4 address")
    _dstIp   := flag.String("dip", "10.0.1.11", "destination IPv4 address")
    _srcPort := flag.Int("sport", 9999, "source udp port")
    _dstPort := flag.Int("dport", 2152, "destination udp port") // GTP-U(2152)
	//_teid    := flag.String("teid", "400-403", "TEID range")
	_teid    := flag.String("teid", "400-403", "TEID range")

    // parse and set command-line options
    flag.Parse()

	device = *_dev
	count = *_count
    srcMac, _ = net.ParseMAC(*_srcMac)
    dstMac, _ = net.ParseMAC(*_dstMac)
	srcIp = net.ParseIP(*_srcIp)
	dstIp = net.ParseIP(*_dstIp)
	srcPort = *_srcPort
	dstPort = *_dstPort
	teid := *_teid
	fmt.Println(teid) // DEBUG
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

	rawBytes := make([]byte, 32)

    gtpLayer := &layers.GTPv1{
        Version: 1,
        ProtocolType: true, // GTP(1)
        MessageType: 1,
        MessageLength: 4,
        SequenceNumberFlag: true, // 1
        TEID: 400, // 0x190
        SequenceNumber: 43690, // 0xAAAA
    }
    udpLayer := &layers.UDP{
        SrcPort  : layers.UDPPort(srcPort),
        DstPort  : layers.UDPPort(dstPort),
    }
    ipv4Layer := &layers.IPv4{
        Version    : 4, //uint8
        IHL        : 5, //uint8
        TOS        : 0, //uint8
        Id         : 0, //uint16
        Flags      : 0, //IPv4Flag
        FragOffset : 0, //uint16
        TTL        : 255, //uint8
        Protocol   : 17, //IPProtocol UDP(17)
        SrcIP: srcIp,
        DstIP: dstIp,
    }
    ethernetLayer := &layers.Ethernet{
        SrcMAC: srcMac,
        DstMAC: dstMac,
        EthernetType: 0x800,
    }

	teidStart, teidEnd, err := parse_range_int(*_teid)
	if err != nil { log.Fatal(err) }

	sum := 1
    for {
        for t := teidStart; t <= teidEnd; t++ {
			gtpLayer.TEID = uint32(t)
            // Actually send packet, and exit if <count> num of packets were sent.
            send_gtp(rawBytes, gtpLayer, udpLayer, ipv4Layer, ethernetLayer)
            sum += 1
            if sum > count { goto END_SENDPACKET }
        }
    }
    END_SENDPACKET:
	return
}

func send_gtp(data []byte,
		gtpLayer *layers.GTPv1,
        udpLayer *layers.UDP,
        ipv4Layer *layers.IPv4,
        ethernetLayer *layers.Ethernet) (err error) {

    buffer = gopacket.NewSerializeBuffer()
    gopacket.SerializeLayers(buffer, options,
        ethernetLayer,
        ipv4Layer,
        udpLayer,
        gtpLayer,
        gopacket.Payload(data),
    )
    err = handle.WritePacketData( buffer.Bytes() )
    if err != nil { log.Fatal(err) }
    return
}

func parse_range_int(value string) (vStart, vEnd int, err error) {
    var v0, v1 int

    if strings.Contains(value, "-") {
        fmt.Println("value:", value) // DEBUG
        values := strings.Split(value, "-")
        if len(values) != 2 {
            err = errors.New("value parse failed.")
            return
        }
        v0, err = strconv.Atoi(values[0])
        if err != nil { return }
        v1, err = strconv.Atoi(values[1])
        if err != nil { return }
        if v0 < v1 {
            vStart = v0
            vEnd = v1
        } else {
            vStart = v1
            vEnd = v0
        }
    } else {
        vStart, err = strconv.Atoi(value)
        if err != nil { return }
        vEnd = vStart
    }
    return
}

