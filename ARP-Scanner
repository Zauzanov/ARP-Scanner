#!/usr/bin/env python3

import time
import scapy.all as scapy

# scanning and returning list of live hosts:
def arp_scan(target: str, iface: str = "eth0", timeout: int = 1) -> list[dict]:
    # build ARP request
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = scapy.ARP(pdst=target)
    packet = ether / arp

    print(f"[*] Starting ARP scan on {target} via {iface}")
    start = time.time()
    
    #send packets and capture responses:
    answered, _ = scapy.srp(packet, timeout=timeout, verbose=False, iface=iface, inter=0.010)
    
    end = time.time()
    print(f"[*] Scan completed in {end - start:.2f} seconds")

    # Extract results:
    hosts = []
    for _, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    return hosts

if __name__ == "__main__":
    subnet = "192.168.204.0/24"   # your IP/Range/CIDR;
    iface = "eth0"                # your NIC;
    hosts = arp_scan(subnet, iface)

    if hosts:
        print("\nLive hosts:")
        for h in hosts:
            print(f"IP: {h['ip']:15}  MAC: {h['mac']}")
    else:
        print("No live hosts found.")
