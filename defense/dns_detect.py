import os

def detect_dns_spoof(log_file='logs/attack_log.txt'):
    with open(log_file, 'r') as f:
        logs = f.read()
        if "example.com" in logs and "5.5.5.5" in logs:
            print("ALERT: Potential DNS Spoofing Detected!")
        else:
            print("No Spoofing Detected")

if __name__ == "__main__":
    detect_dns_spoof()