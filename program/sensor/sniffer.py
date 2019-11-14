import socket
from extract_headers import *

#Ethernet Types
ip_protocol = 0x0800
#IP Protocols
tcp_protocol = 0x06
icmp_protocol = 0x01
udp_protocol = 0x011

def sniffer():
    #Address family: AF_INET, Scoket type: SOCK_RAW, Protocol: ETH_P_ALL (0x003)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0003))
    
    #Recieve packets
    while True:
        packet = s.recvfrom(65565)
        ethernet_header = extract_ethernet_header(packet)

        if ethernet_header['Ethernet Type'] is ip_protocol:
            ip_header = extract_ip_header(packet)

            if ip_header['Protocol'] is tcp_protocol:
                tcp_header = extract_tcp_header(packet)

            elif ip_header['Protocol'] is icmp_protocol:
                icmp_header = extract_icmp_header(packet)

            elif ip_header['Protocol'] is udp_protocol:
                udp_header = extract_udp_header(packet)

if __name__ == '__main__':
    sniffer()
