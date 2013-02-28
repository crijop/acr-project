#!/usr/bin/python
from pcapy import *
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP

decoder = EthDecoder()


def callback(jdr, data):
    packet = decoder.decode(data)
    child = packet.child()
    if isinstance(child, IP):
        child = child.child()
        if isinstance(child, TCP):
            if child.get_th_dport() == 993:
                print 'IMAP'
                print dir(child)
                print child.get_data_as_string()
                print child.get_buffer_as_string()
                print child.get_bytes()

    pass


#IMAP Port 143
#IMAP SSL Port 993
#IMAP StartTLS Port 143

#list all devices
devices = findalldevs()
print devices

#ask user to enter device name to sniff
print "Available devices are :"
for d in devices :
    print d

dev = raw_input("Enter device name to sniff : ")

print "Sniffing device " + dev
pcap = open_offline('captura.pcap')
pcap.loop(0, callback)
