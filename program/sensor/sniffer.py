from collections import namedtuple
from detector.detector import scan_packet

import socket
import struct

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def nids_sniffer():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        destination_mac, source_mac, ethernet_protocol, data = ethernet_frame(raw_data)

        Ethernet_Frame = collections.namedtuple('Ethernet_Frame', ['destination_mac', 'source_mac', 'ethernet_protocol'])
        ethernet_frame = Ethernet_Frame(destination_mac, source_mac, ethernet_protocol)

        #8 for IPv4
        if ethernet_protocol == 8:
            version, header_length, ttl, protocol, source, target, data = ipv4_packet(data)

            IPV4 = collections.namedtuple('IPV', ['version', 'header_length', 'ttl', 'protocol', 'source', 'target'])
            ipv4 = IPV4(version, header_length, ttl, protocol, source, target)

            #ICMP
            if protocol == 1:
                icmp_type, code, checksum, data = icmp_segment(data)

                ICMP = collections.namedtuple('ICMP', ['tcmp_type', 'code', 'checksum', 'data'])
                icmp = ICMP(icmp_type, code, checksum, data)

                Packet_ICMP = collections.namedtuple('Packet_ICMP', ['ethernet_frame', 'ipv4', 'icmp'])
                packet_icmp = Packet_ICMP(ethernet_frame, ipv4, icmp)
                
                scan_packet(packet_icmp)

            #TCP
            elif protocol == 6:
                source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

                TCP = collections.namedtuple('TCP', ['source_port', 'destination_port', 'sequence', 'acknowledgment', 'flag_urg', 'flag_ack', 'flag_psh', 'flag_rst', 
                    'flag_syn', 'flag_fin', 'data'])
                tcp = TCP(source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data)

                Packet_TCP = collections.namedtuple('Packet_TCP', ['ethernet_frame', 'ipv4', 'tcp'])
                packet_tcp = Packet_TCP(ethernet_frame, ipv4, tcp)

                scan_packet(packet_tcp)

            #UDP
            elif protocol == 17:
                source_port, destination_port, length, data = udp_segment(data)

                UDP = collections.namedtuple('UDP', ['source_port', 'destination_port', 'length', 'data'])
                udp = UDP(source_port, destination_port, length, data)

                Packet_UDP = collections.namedtuple('Packet_UDP', ['ethernet_frame', 'ipv4', 'udp'])
                packet_udp = Packet_UDP(ethernet_frame, ipv4, udp)

                scan_packet(packet_udp)
                
            else:
                Packet_Other = collections.namedtuple('Packet_Other', ['ethernet_frame', 'ipv4', 'other'])
                packet_other = Packet_Other(ethernet_frame, ipv4)

                scan_packet(packet_other)


def packet_sniffer():
    output = open('sniffer_output.txt', 'w+')

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        destination_mac, source_mac, ethernet_protocol, data = ethernet_frame(raw_data)

        output.write('\nEthernet Frame:')
        output.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, ethernet_proto))

        #8 for IPv4
        if ethernet_protocol == 8:
            version, header_length, ttl, protocol, source, target, data = ipv4_packet(data)

            output.write(TAB_1 + 'IPv4 Packet:')
            output.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            output.write(TAB_2 + 'Protocol: {}, Source, {}, Target: {}'.format(protocol, source, target))

            #ICMP
            if protocol == 1:
                icmp_type, code, checksum, data = icmp_segment(data)

                output.write(TAB_1 + 'ICMP Packet:')
                output.write(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                output.write(TAB_2 + 'Data:')
                output.write(format_multi_line(DATA_TAB_3, data))

            #TCP
            elif protocol == 6:
                source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

                output.write(TAB_1 + 'TCP Segment:')
                output.write(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(source_port, destination_port))
                output.write(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgment))
                output.write(TAB_2 + 'Flags:')
                output.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                output.write(TAB_2 + 'Data:')
                output.write(format_multi_line(DATA_TAB_3, data))

            #UDP
            elif protocol == 17:
                source_port, destination_port, length, data = udp_segment(data)

                output.write(TAB_1 + 'UDP Segment:')
                output.write(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(source_port, destination_port, length))
                output.write(TAB_2 + 'Data:')
                output.write(format_multi_line(DATA_TAB_3, data))

            else:
                output.write(TAB_1 + 'Data:')
                output.write(format_multi_line(DATA_TAB_2, data))


#Unpack ethernet frame
def ethernet_frame(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(destination_mac), get_mac_addr(source_mac), socket.htons(protocol), data[14:]

#Return properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(source), ipv4(target), data[header_length:]

#Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

#Unpacks ICMP packet
def icmp_segment(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpacks TCP segment
def tcp_segment(data):
    (source_port, destination_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpacks UDP segment
def udp_segment(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#Formats multi-line data
def format_multi_line(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
