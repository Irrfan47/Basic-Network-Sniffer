from scapy.all import sniff, Ether, IP, TCP, UDP, Raw

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    print("\n--- Packet Captured ---")

    # Check if the packet has an Ethernet layer
    if Ether in packet:
        print(f"Ethernet Frame: Source MAC = {packet[Ether].src}, Destination MAC = {packet[Ether].dst}")

    # Check if the packet has an IP layer
    if IP in packet:
        print(f"IP Packet: Source IP = {packet[IP].src}, Destination IP = {packet[IP].dst}")

    # Check if the packet has a TCP layer
    if TCP in packet:
        print(f"TCP Segment: Source Port = {packet[TCP].sport}, Destination Port = {packet[TCP].dport}")

    # Check if the packet has a UDP layer
    if UDP in packet:
        print(f"UDP Datagram: Source Port = {packet[UDP].sport}, Destination Port = {packet[UDP].dport}")

    # Check if the packet has a Raw layer (payload)
    if Raw in packet:
        print(f"Payload (Raw Data): {packet[Raw].load}")

    print("--- End of Packet ---\n")

def start_sniffer(interface=None, count=10):
    """
    Start sniffing network traffic on the specified interface.
    :param interface: Network interface to sniff on (e.g., 'eth0'). If None, uses the default interface.
    :param count: Number of packets to capture. If 0, captures indefinitely.
    """
    print(f"Starting network sniffer on interface {interface if interface else 'default'}...")
    sniff(iface=interface, prn=packet_callback, count=count)

if __name__ == "__main__":
    # Specify the network interface (e.g., 'eth0', 'wlan0') or leave as None for the default interface
    interface = None

    # Start the sniffer
    start_sniffer(interface=interface, count=10)  # Capture 10 packets