package arp

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/iesreza/netconfig"
	"net"
)

var defaultSerializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

type Address struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

var Table = map[[4]byte]net.HardwareAddr{}
var SrcHardwareAddr = netconfig.GetNetworkConfig().HardwareAddress
var SrcIPAddr = netconfig.GetNetworkConfig().LocalIP.To4()

func LookupIP(ip []byte) *net.HardwareAddr {
	if len(ip) == 4 {
		if val, ok := Table[[4]byte{ip[0], ip[1], ip[2], ip[3]}]; ok {
			return &val
		}
	} else if len(ip) == 16 {
		if val, ok := Table[[4]byte{ip[12], ip[13], ip[14], ip[15]}]; ok {
			return &val
		}
	}
	return nil

}

func WhoHas(ip net.IP) []byte {
	// Set up all the layers' fields we can.
	var src []byte
	src = ip.To4()
	eth := layers.Ethernet{
		SrcMAC:       SrcHardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, //Broadcast
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   SrcHardwareAddr,
		SourceProtAddress: src,
		DstProtAddress:    src,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0}, //Broadcast
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, defaultSerializeOpts, &eth, &arp)

	return buf.Bytes()
}

func IsAt(src Address, target Address) []byte {
	//log.Warning("Tell " + target.IP.String() + " ? " + src.IP.String() + " is at " + src.HardwareAddr.String())
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
		SrcMAC:       src.HardwareAddr,
		DstMAC:       target.HardwareAddr,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		Operation:         layers.ARPReply,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		SourceHwAddress:   src.HardwareAddr,
		SourceProtAddress: src.IP.To4(),
		DstHwAddress:      target.HardwareAddr,
		DstProtAddress:    target.IP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, defaultSerializeOpts, &eth, &arp)

	return buf.Bytes()
}

func Listen(source *pcap.Handle, onReply func(srcAddress Address, replyTo Address), onRequest func(ip net.IP, replyTo Address)) {
	src := gopacket.NewPacketSource(source, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arpPacket := arpLayer.(*layers.ARP)

			if arpPacket.Operation == layers.ARPRequest {
				if bytes.Equal([]byte(SrcHardwareAddr), arpPacket.SourceHwAddress) {
					continue
				}
				if onRequest != nil {
					onRequest(net.IP(arpPacket.DstProtAddress), Address{
						net.IP(arpPacket.SourceProtAddress), net.HardwareAddr(arpPacket.SourceHwAddress),
					})
				}
			}
			if arpPacket.Operation == layers.ARPReply {
				if onReply != nil {
					onReply(Address{
						net.IP(arpPacket.SourceProtAddress), net.HardwareAddr(arpPacket.SourceHwAddress),
					}, Address{
						net.IP(arpPacket.DstProtAddress), net.HardwareAddr(arpPacket.DstHwAddress),
					})
				}
			}
		}
	}

}
