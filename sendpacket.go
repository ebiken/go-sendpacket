package main

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "net"
    "time"
    "flag"
//    "fmt"
)

var (
    device       string = "enp8s0f1" // i40e
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
    buffer       gopacket.SerializeBuffer
    options      gopacket.SerializeOptions
)


func main() {
    // command-line flags
    _srcMac := flag.String("sm", "02:00:00:00:00:01", "source MAC")
    _dstMac := flag.String("dm", "06:00:00:00:00:01", "destination MAC")
    _srcIp  := flag.String("si", "127.0.0.2", "source IPv4 address")
    _dstIp  := flag.String("di", "10.0.0.10", "destination IPv4 address")
    srcPort := flag.Int("sp", 10, "source udp port")
    dstPort := flag.Int("dp", 0, "destination udp port")

    flag.Parse()

    srcMac, _ := net.ParseMAC(*_srcMac)
    dstMac, _ := net.ParseMAC(*_dstMac)
    srcIp := net.ParseIP(*_srcIp)
    dstIp := net.ParseIP(*_dstIp)

    // fmt.Println("srcMac:", srcMac)
    // fmt.Println("dstMac:", dstMac)
    // fmt.Println("srcIp:", srcIp)
    // fmt.Println("dstIp:", dstIp)
    // fmt.Println("srcPort:", *srcPort)
    // fmt.Println("dstPort:", *dstPort)

    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    rawBytes := []byte{10, 20, 30}

    // DEBUG : Send raw bytes over wire
    //err = handle.WritePacketData(rawBytes)
    //if err != nil {
    //    log.Fatal(err)
    // }

    ethernetLayer := &layers.Ethernet{
        SrcMAC: srcMac,
        DstMAC: dstMac,
    	EthernetType: 0x800,
    }
    ipLayer := &layers.IPv4{
        Version    : 4, //uint8
        IHL        : 5, //uint8
        TOS        : 0, //uint8
        Length     : 46, //uint16
        Id         : 0, //uint16
        Flags      : 0, //IPv4Flag
        FragOffset : 0, //uint16
        TTL        : 255, //uint8
        Protocol   : 17, //IPProtocol UDP(17)
        //Checksum   uint16
        SrcIP: srcIp,
        DstIP: dstIp,
	    //Options    []IPv4Option
        //Padding    []byte
    }
    udpLayer := &layers.UDP{
        SrcPort  : layers.UDPPort(*srcPort),
        DstPort  : layers.UDPPort(*dstPort),
        Length   : 26, // uint16
        //Checksum : , // uint16
        // ?? sPort    : , // []byte
        // ?? dPort    : , // []byte
        // ?? tcpipchecksum
    }
    // And create the packet with the layers
    buffer = gopacket.NewSerializeBuffer()
    gopacket.SerializeLayers(buffer, options,
        ethernetLayer,
        ipLayer,
        udpLayer,
        gopacket.Payload(rawBytes),
    )
    outgoingPacket := buffer.Bytes()

    err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        log.Fatal(err)
    }
}
