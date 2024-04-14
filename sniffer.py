from scapy.all import *

interface = 'wlan0'
probeReqs = []

def sniffProbes(p):
    if p.haslayer(Dot11ProbeReq):
        netName = p.getlayer(Dot11ProbeReq).info.decode()
        if netName not in probeReqs:
            probeReqs.append(netName)
            print('[+] Detected Probe Requests: ' + netName)

sniff(iface=interface, prn=sniffProbes)
