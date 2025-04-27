import os
from scapy.all import sniff, IP, TCP, UDP

BLOCKED_IPS = ["192.168.1.100", "8.8.8.8"]
BLOCKED_PORTS = [22, 23, 443]  

def block_ip(ip):
    print(f"[!] Blocking IP {ip} using Windows Firewall")
    os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')

def block_port(port):
    print(f"[!] Blocking Port {port} using Windows Firewall")
    os.system(f'netsh advfirewall firewall add rule name="Block Port {port}" dir=in action=block protocol=TCP localport={port}')

def monitor_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip in BLOCKED_IPS:
            print(f"[!] Detected traffic from blocked IP: {src_ip}")
            block_ip(src_ip)

    if TCP in packet or UDP in packet:
        proto = "TCP" if TCP in packet else "UDP"
        dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
        if dport in BLOCKED_PORTS:
            print(f"[!] Detected traffic to blocked {proto} port: {dport}")
            block_port(dport)

print("[*] Starting simple firewall... Press Ctrl+C to stop.")
sniff(filter="ip", prn=monitor_packet, store=0)
