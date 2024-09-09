import scapy.all as scapy
import logging

logging.basicConfig(filename='dns_detection.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def detect_spoof(packet):
    if packet.haslayer(scapy.DNSRR):
        real_ip = "1.2.3.4"  # Expected IP address
        response_ip = packet[scapy.DNSRR].rdata
        if response_ip != real_ip:
            logging.info(f"Spoof detected: {response_ip} != {real_ip}")
            print(f"Potential DNS Spoofing Detected: {response_ip}")

print("Starting DNS detection...")
scapy.sniff(filter="udp port 53", store=False, prn=detect_spoof)
