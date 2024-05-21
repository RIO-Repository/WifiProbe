from scapy.all import *
from datetime import datetime
import logging

# Configuration
interface = 'wlan0'
probe_reqs = {}
log_file = 'probe_requests.log'

# Set up logging
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

def sniff_probes(packet):
    if packet.haslayer(Dot11ProbeReq):
        ssid = packet[Dot11ProbeReq].info.decode(errors='ignore')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if ssid not in probe_reqs:
            probe_reqs[ssid] = 1
            log_probe(timestamp, ssid)
            print(f'[+] Detected Probe Request: {ssid}')
        else:
            probe_reqs[ssid] += 1

def log_probe(timestamp, ssid):
    logger.info(f'{timestamp} - {ssid}')

def start_sniffing(interface):
    print(f'Starting sniffing on interface {interface}...')
    try:
        sniff(iface=interface, prn=sniff_probes)
    except PermissionError as e:
        print(f"Error: {e}. Please run the script with elevated privileges.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    start_sniffing(interface)
