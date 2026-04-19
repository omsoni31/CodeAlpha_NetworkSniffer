from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    print("\n--- Packet Captured ---")
    
    if packet.haslayer(IP):
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)
    
    if packet.haslayer(TCP):
        print("Protocol: TCP")
    elif packet.haslayer(UDP):
        print("Protocol: UDP")
    else:
        print("Protocol: Other")
    
    print("Summary:", packet.summary())

print("Starting Network Sniffer...")
sniff(prn=packet_callback, count=10)
