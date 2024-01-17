import os
import sys
import time
from threading import Thread
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11
import argparse
import subprocess

networks = {}

NETWORK_TIMEOUT = 30

def update_networks():
    current_time = time.time()
    expired_networks = [bssid for bssid, data in networks.items() if current_time - data['last_seen'] > NETWORK_TIMEOUT]
    for bssid in expired_networks:
        del networks[bssid]

def packet_handler(packet):
    if packet.haslayer(Dot11):
        bssid = packet[Dot11].addr2
        current_time = time.time()

        if bssid not in networks:
            networks[bssid] = {'ssid': None, 'pwr': 'N/A', 'beacons': 0, 'data': 0, 'channel': None, 'encryption': set(), 'last_seen': current_time}
        else:
            networks[bssid]['last_seen'] = current_time

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else None
            stats = packet[Dot11Beacon].network_stats() if packet.haslayer(Dot11Beacon) else None
            channel = stats.get("channel") if stats else None
            encryption = stats.get("crypto") if stats else None

            networks[bssid].update({
                'ssid': ssid,
                'channel': channel,
                'encryption': encryption
            })
            if packet.haslayer(Dot11Beacon):
                networks[bssid]['beacons'] += 1

        if packet.type == 0 and packet.subtype in [0x00, 0x04, 0x08, 0x05]:
            networks[bssid]['data'] += 1



def print_networks():
    os.system('clear')
    print("BSSID\t\t\tPWR\tBeacons\t#Data\tCH\tENC\t\tESSID")
    print("-------------------------------------------------------------------------------------")
    for bssid, info in list(networks.items()):
        enc = ', '.join(info['encryption']) if info['encryption'] else 'N/A\t'
        print(f"{bssid}\t{info['pwr']}\t{info['beacons']}\t{info['data']}\t{info['channel'] or 'N/A'}\t{enc}\t{info['ssid'] or 'N/A'}")

def is_monitor_mode(interface):
    try:
        iwconfig_output = subprocess.check_output(['iwconfig', interface], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        print(f"Error: Interface '{interface}' not found.")
        return False

    return "Mode:Monitor" in iwconfig_output


def scan_wifi_networks(interface):
    sniff(iface=interface, prn=packet_handler, store=False)


def main():
    parser = argparse.ArgumentParser(description='Wireless network scanner')
    parser.add_argument('interface', type=str, help='Wireless interface for scanning')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script must be run as root to perform network sniffing.")
        sys.exit(1)

    if not is_monitor_mode(args.interface):
        print(f"Error: Interface '{args.interface}' is not in monitor mode.")
        exit(1)

    # Start a separate thread for sniffing
    sniffer = Thread(target=scan_wifi_networks, args=(args.interface,))
    sniffer.daemon = True
    sniffer.start()

    try:
        while True:
            update_networks()
            print_networks()
            time.sleep(1)  # Refresh rate
    except KeyboardInterrupt:
        print("Stopping scanner")
        os._exit(0)


if __name__ == '__main__':
    main()
