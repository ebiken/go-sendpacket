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


func main() {
    // command-line flags
    _srcMac := flag.String("sm", "02:00:00:00:00:01", "source MAC")
    _dstMac := flag.String("dm", "06:00:00:00:00:01", "destination MAC")
    _srcIp  := flag.String("si", "127.0.0.2", "source IPv4 address")
    _dstIp  := flag.String("di", "10.0.0.10", "destination IPv4 address")
    _srcPort := flag.Int("sp", 10, "source udp port")
    _dstPort := flag.Int("dp", 0, "destination udp port")
    _count  := flag.Int("c", 1, "repeat count")

    flag.Parse()

    srcMac, _ = net.ParseMAC(*_srcMac)
    dstMac, _ = net.ParseMAC(*_dstMac)
    srcIp = net.ParseIP(*_srcIp)
    dstIp = net.ParseIP(*_dstIp)
    srcPort = *_srcPort
    dstPort = *_dstPort
    count = *_count

    //options.FixLengths = false
    options.FixLengths = true
    //options.ComputeChecksums = false
    options.ComputeChecksums = true

    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    //rawBytes := make([]byte, 992)
    rawBytes := make([]byte, 200)

    // DEBUG : Send raw bytes over wire
    //err = handle.WritePacketData(rawBytes)
    //if err != nil {
    //    log.Fatal(err)
    // }

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
        //Length   : 100, // uint16
        //Checksum : xxx, // uint16
    }

    ethernetLayer := &layers.Ethernet{
        SrcMAC: srcMac,
        DstMAC: dstMac,
        EthernetType: 0x800,
    }


    sum := 0
    for sum < count {
        send_udp(rawBytes, udpLayer, ipv4Layer, ethernetLayer)
        sum += 1
    }
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



