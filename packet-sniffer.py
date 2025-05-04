from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    """
    Callback function to process captured packets.
    """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")

        if TCP in packet:
            print(f"  TCP Packet: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
        elif UDP in packet:
            print(f"  UDP Packet: {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")

def main():
    """
    Main function to start packet sniffing.
    """
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()