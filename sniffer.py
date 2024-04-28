from scapy.all import *
from datetime import datetime

interface = 'wlan0'
probeReqs = {}

def sniffProbes(p):
    if p.haslayer(Dot11ProbeReq):
        ssid = p.getlayer(Dot11ProbeReq).info.decode()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if ssid not in probeReqs:
            probeReqs[ssid] = 1
            log_probe(timestamp, ssid)
            print(f'[+] Detected Probe Request: {ssid}')
        else:
            probeReqs[ssid] += 1

def log_probe(timestamp, ssid):
    with open('probe_requests.log', 'a') as log_file:
        log_file.write(f'{timestamp} - {ssid}\n')

def start_sniffing(interface):
    print(f'Starting sniffing on interface {interface}...')
    sniff(iface=interface, prn=sniffProbes)

if __name__ == "__main__":
    start_sniffing(interface)
