import sys
from datetime import *

print "**********************************"
print "*** ARPScan v0.1"    
print "*** Support: manuel.zarat@gmail.com"    
print "*** powered by Python und Scapy" 
print "*** this software is for educational purposes only."
print "*** just penetrate networks that you own or have permission to."
print "*** i am not responsible for any misuse."    
print "**********************************"

try:
	interface = raw_input("[*] interface eingeben (eth0, wlan0,...): ")
	ips = raw_input("[*] ip/range eingeben: ")

except KeyboardInterrupt:
	print ""
	sys.exit(1)

from scapy.all import srp,Ether,ARP,conf

conf.verb = 0
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=interface, inter=0.1)

print "MAC IP's\n"

for snd,rcv in ans:
	print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")
