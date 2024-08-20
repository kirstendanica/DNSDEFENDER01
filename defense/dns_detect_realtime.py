from scapy.all import *
import time

def dns_detect(pkt):
    if pkt.haslayer(DNSRR):
        # Check if response contains the spoofed IP address
        if pkt[DNSRR].rdata == "5.5.5.5" and pkt[DNSRR].rrname == b"example.com.":
            print(f"[ALERT] DNS spoofing detected for {pkt[DNSRR].rrname.decode()}!")
            print(f"Time: {time.ctime()} | Spoofed IP: {pkt[DNSRR].rdata}")

def main():
    print("Starting real-time DNS spoof detecter in 3...2...1...")
    sniff(filter="udp port 53", prn=dns_detect)

if __name__ == "__main__":
    main()
