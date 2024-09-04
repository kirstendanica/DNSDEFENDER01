import scapy.all as scapy
import sys

def detect_spoof(packet, real_ip, domain):
    if packet.haslayer(scapy.DNSRR):
        dns_resp = packet[scapy.DNSRR].rdata
        if packet[scapy.DNSQR].qname.decode('utf-8') == domain:
            if dns_resp != real_ip:
                print(f"Spoofed DNS detected! {dns_resp} does not match {real_ip}")

if len(sys.argv) != 3:
    print("Usage: python dns_detect_realtime.py <expected IP> <domain>")
    sys.exit(1)

expected_ip = sys.argv[1]
target_domain = sys.argv[2]

print(f"Monitoring DNS traffic for domain: {target_domain} and IP: {expected_ip}")
scapy.sniff(filter="udp port 53", store=False, prn=lambda pkt: detect_spoof(pkt, expected_ip, target_domain))
