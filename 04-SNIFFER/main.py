from scapy.all import sniff, I
P, TCP, UDP, ARP
from collections import defaultdict
import signal
import sys


def signal_handler(sig, frame):
    print("\n[INFO] Arrêt du sniffer proprement.")
    sys.exit(0)


# Gestion des scans de ports
tcp_flags_count = defaultdict(int)
arp_requests = defaultdict(int)


def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Autre"
        print(f"[INFO] Paquet capturé: {src_ip} -> {dst_ip} ({proto})")

        # Détection de scan de ports SYN
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # Flag SYN uniquement
            tcp_flags_count[src_ip] += 1
            if tcp_flags_count[src_ip] > 10:
                print(f"[ALERTE] Possible scan de ports détecté depuis {src_ip}")

    # Détection de requêtes ARP suspectes
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # Requête ARP
        arp_requests[packet[ARP].psrc] += 1
        if arp_requests[packet[ARP].psrc] > 5:
            print(f"[ALERTE] Activité ARP suspecte détectée depuis {packet[ARP].psrc}")


# Gestion des signaux pour un arrêt propre
signal.signal(signal.SIGINT, signal_handler)

print("[INFO] Démarrage du sniffer réseau...")
# Capture en mode promiscuité sur l'interface principale
sniff(prn=packet_handler, store=0)
