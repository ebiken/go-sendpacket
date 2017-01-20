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

type IPv4Range struct {
    sipStart    net.IP
    dipStart    net.IP
    sipEnd      net.IP
    dipEnd      net.IP
    sip         net.IP
    dip         net.IP
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
    _count   := flag.Int("count", 1, "repeat count")
    _srcMac  := flag.String("smac", "02:00:00:00:00:01", "source MAC")
    _dstMac  := flag.String("dmac", "06:00:00:00:00:01", "destination MAC")
    _srcIp   := flag.String("sip", "127.0.0.2-9", "source IPv4 address range")
    _dstIp   := flag.String("dip", "10.0.1-3.11", "destination IPv4 address range")
    _srcPort := flag.String("sport", 11-13, "source udp port range")
    _dstPort := flag.String("dport", 41-43, "destination udp port range")

    flag.Parse()

    count = *_count
    srcMac, _ = net.ParseMAC(*_srcMac)
    dstMac, _ = net.ParseMAC(*_dstMac)

    ipv4range := IPv4Range{
        sip: net.ParseIP("127.0.0.2"),
        sipStart: net.ParseIP("127.0.0.2"),
        sipEnd: net.ParseIP("127.0.0.3"),
        dip: net.ParseIP("10.0.1.1"),
        dipStart: net.ParseIP("10.0.1.1"),
        dipEnd: net.ParseIP("10.0.3.3"),
    }
    // debug
    sportStart := 21
    sportEnd := 21
    dportStart := 31
    dportEnd := 31

    //options.FixLengths = false
    options.FixLengths = true
    //options.ComputeChecksums = false
    options.ComputeChecksums = true

    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    rawBytes := make([]byte, 200)

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
    udpLayer := &layers.UDP{
        SrcPort  : layers.UDPPort(srcPort),
        DstPort  : layers.UDPPort(dstPort),
    }

    ethernetLayer := &layers.Ethernet{
        SrcMAC: srcMac,
        DstMAC: dstMac,
        EthernetType: 0x800,
    }

    // send packets: Loop = { IP src { IP dst { L4 src { L4 dst } } } }
    sum := 1
    for {

        ipv4Layer.SrcIP = ipv4range.sip // TODO: should not copy pointer.
        ipv4Layer.DstIP = ipv4range.dip // TODO: should not copy pointer.

        for sport := sportStart; sport <= sportEnd; sport++ {
            udpLayer.SrcPort = layers.UDPPort(sport)

            for dport := dportStart; dport <= dportEnd; dport++ {
                udpLayer.DstPort = layers.UDPPort(dport)

                // Actually send packet, and exit if <count> num of packets were sent.
                send_udp(rawBytes, udpLayer, ipv4Layer, ethernetLayer)
                sum += 1
                if sum > count { goto END_SENDPACKET }
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
    fmt.Println("called: send_udp")

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
    fmt.Println("called: send_ipv4")

    buffer_ipv4 := gopacket.NewSerializeBuffer()
    gopacket.SerializeLayers(buffer_ipv4, options,
        ipv4Layer,
        gopacket.Payload(data),
    )
    return send_ethernet(buffer_ipv4.Bytes(), ethernetLayer)
}

func send_ethernet(data []byte,
        ethernetLayer *layers.Ethernet) (err error) {
    fmt.Println("called: send_ethernet")

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



