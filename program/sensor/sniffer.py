#Basic Packet sniffer, not working version

import socket
from extract_headers import *

def sniffer():
    #Ethernet Types
    ip_protocol = 0x0800
    #IP Protocols
    tcp_protocol = 0x06
    icmp_protocol = 0x01
    udp_protocol = 0x011

    #Address family: AF_INET, Scoket type: SOCK_RAW, Protocol: ETH_P_ALL (0x003)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))
    print("Created socket: Waiting for connection...")

    #Recieve packets
    while True:
        packet = s.recvfrom(65565)
        print(packet)

        #ethernet_header = extract_ethernet_header(packet)
        #print("Obtained ethernet packet: Parsing...")
        #print(ethernet_header)

        #ip_header = extract_ip_header(packet)
        #print("Obtained ip packet: Parsing...")
        #print(ip_header)

        #if ip_header['Protocol'] is tcp_protocol:
        #    tcp_header = extract_tcp_header(packet)
        #    print("Obtained tcp packet: Parsing...")
        #    print(tcp_header)

        #elif ip_header['Protocol'] is icmp_protocol:
        #    icmp_header = extract_icmp_header(packet)
        #    print("Obtained icmp packet: Parsing...")
        #    print(icmp_header)

        #elif ip_header['Protocol'] is udp_protocol:
        #    udp_header = extract_udp_header(packet)
        #    print("Obtained udp packet: Parsing...")
        #    print(udp_header)

if __name__ == '__main__':
    sniffer()
