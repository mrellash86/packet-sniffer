This program is a packet sniffer built using Python and the Scapy library. Its primary functionality is to capture and analyze network packets in real-time. Here's a breakdown of its features:

 Program Description
The packet sniffer captures network traffic and processes each packet to extract and display key information, such as source and destination IP addresses, protocols, and port numbers for TCP and UDP packets.

 Functionality
1. Packet Capture:
   - The program uses Scapy's `sniff()` function to capture packets from the network.
   - Captured packets are passed to a callback function for processing.

2. Packet Analysis:
   - The `packet_callback` function checks if the packet contains an IP layer.
   - If an IP layer is present, it extracts:
     - Source IP address
     - Destination IP address
     - Protocol type
   - If the packet contains TCP or UDP layers, it further extracts:
     - Source and destination port numbers.

3. Real-Time Output:
   - The program prints the extracted information to the console in real-time, providing insights into the network traffic.

4. Ease of Use:
   - The program starts sniffing packets when executed and can be stopped using `Ctrl+C`.

 Usage
This program is useful for network monitoring, debugging, or learning about network protocols. It provides a simple yet powerful way to observe network traffic on a system.
