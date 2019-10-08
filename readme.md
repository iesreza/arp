# ARP Library
This package implements two function of "WhoHas" and "IsAt" functions and also listen for arp packets using pcap.

An ARP spoofer has implemented as a test.

```
    //Ask who has 192.168.0.1
    packetBytes := arp.WhoHas(net.ParseIP("192.168.0.1"))
    
    
    //Tell to target that 192.168.0.1 is at my desired mac
    var fakeDevice := arp.Address{
        IP:net.ParseIP("192.168.0.1"),
        HardwareAddr : 	net.ParseMAC("xx:xx:xx:xx:xx")
    }
    var target := arp.Address{
            IP:net.ParseIP("192.168.0.2"),
            HardwareAddr : 	net.ParseMAC("yy:yy:yy:yy:yy")
    }
    packetBytes = arp.IsAt(fakeDevice,target)
    
    
    //Listen to incoming arp packets
    
    handler, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handler.Close()
    arp.Listen(handler, func(srcAddress arp.Address,replyTo arp.Address) {
        log.Info("%s is at %s \n",srcAddress.IP.String(),srcAddress.HardwareAddr.String())
    }, func(ip net.IP,replyTo arp.Address) {
        log.Info("Who has %s? Tell %s \n",ip.String(),replyTo.IP.String())
    })
``` 