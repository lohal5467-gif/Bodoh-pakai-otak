# Bodoh-pakai-otak
# Skrip edukasi: Deteksi penggunaan WhatsApp di jaringan
from scapy.all import *

def detect_whatsapp_traffic(packet):
    """Deteksi traffic WhatsApp untuk analisis keamanan jaringan"""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Deteksi berdasarkan port umum WhatsApp
        if packet.haslayer(TCP):
            if packet[TCP].dport in [5222, 443, 80]:
                print(f"[DETECTED] Possible WhatsApp traffic: {src_ip} -> {dst_ip}:{packet[TCP].dport}")
                # Log untuk analisis lebih lanjut
                return True
    return False

# Konsep sniffing untuk penelitian
# sniff(filter="tcp", prn=detect_whatsapp_traffic, store=0)
