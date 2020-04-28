#Referenced youtube tutorials "Python Network Packet Snifffer Tutorials" from "thenewboston" 
#when creating the basic packet sniffer before modifying it

import collections
from detector.detector import scan_packet
import subprocess
import socket
import struct
import textwrap
import datetime
import urllib.request

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def nids_sniffer():
    this_systems_ips = get_ips()
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True: 
        raw_data, addr = conn.recvfrom(65536)
        DT = datetime.datetime.now()
        destination_mac, source_mac, ethernet_protocol, data = format_ethernet_frame(raw_data)
 
        Ethernet_Frame = collections.namedtuple('Ethernet_Frame', ['destination_mac', 'source_mac', 'ethernet_protocol', 'date_time'])
        ethernet_frame = Ethernet_Frame(destination_mac, source_mac, str(ethernet_protocol), str(DT))

        #8 for IPv4
        if ethernet_protocol == 8:
            version, header_length, ttl, protocol, source, target, data = ipv4_packet(data)

            check = True
            for ip in this_systems_ips:
                if ip == source:
                    check = False

            if check == True:              
                IPV4 = collections.namedtuple('IPV', ['version', 'header_length', 'ttl', 'protocol', 'source', 'target'])
                ipv4 = IPV4(str(version), str(header_length), str(ttl), str(protocol), source, target)

                #ICMP
                if protocol == 1:
                    icmp_type, code, checksum, data = icmp_segment(data)

                    ICMP = collections.namedtuple('ICMP', ['icmp_type', 'code', 'checksum', 'data'])
                    icmp = ICMP(str(icmp_type), str(code), str(checksum), format_data(data))

                    Packet_ICMP = collections.namedtuple('Packet_ICMP', ['ethernet_frame', 'ipv4', 'icmp'])
                    packet_icmp = Packet_ICMP(ethernet_frame, ipv4, icmp)
                
                    scan_packet(packet_icmp)

                #TCP
                elif protocol == 6:
                    source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

                    TCP = collections.namedtuple('TCP', ['source_port', 'destination_port', 'sequence', 'acknowledgment', 'flag_urg', 'flag_ack', 'flag_psh', 'flag_rst', 
                    'flag_syn', 'flag_fin', 'data'])
                    tcp = TCP(str(source_port), str(destination_port), str(sequence), str(acknowledgment), str(flag_urg), str(flag_ack), str(flag_psh), str(flag_rst), str(flag_syn), str(flag_fin), format_data(data))

                    Packet_TCP = collections.namedtuple('Packet_TCP', ['ethernet_frame', 'ipv4', 'tcp'])
                    packet_tcp = Packet_TCP(ethernet_frame, ipv4, tcp)

                    scan_packet(packet_tcp)

                #UDP
                elif protocol == 17:
                    source_port, destination_port, length, data = udp_segment(data)

                    UDP = collections.namedtuple('UDP', ['source_port', 'destination_port', 'length', 'data'])
                    udp = UDP(str(source_port), str(destination_port), str(length), format_data(data))

                    Packet_UDP = collections.namedtuple('Packet_UDP', ['ethernet_frame', 'ipv4', 'udp'])
                    packet_udp = Packet_UDP(ethernet_frame, ipv4, udp)

                    scan_packet(packet_udp)
                
                else:
                    Packet_Other = collections.namedtuple('Packet_Other', ['ethernet_frame', 'ipv4', 'other'])
                    packet_other = Packet_Other(ethernet_frame, ipv4, format_data(data))

                    scan_packet(packet_other)


def packet_sniffer():
    output = open('database/sniffer_output.txt', 'a+')
    this_systems_ips = get_ips()

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        DT = datetime.datetime.now()
        destination_mac, source_mac, ethernet_protocol, data = format_ethernet_frame(raw_data)

        #8 for IPv4
        if ethernet_protocol == 8:
            version, header_length, ttl, protocol, source, target, data = ipv4_packet(data)

            check = True
            for ip in this_systems_ips:
                if ip == source:
                    check = False

            if check == True:
                #ICMP
                if protocol == 1:
                    icmp_type, code, checksum, data = icmp_segment(data)

                    output.write('Date and Time: {}\n'.format(DT))
                    output.write('Ethernet Frame:\n')
                    output.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'.format(destination_mac, source_mac, ethernet_protocol))

                    print('Date and Time: {}'.format(DT))
                    print('Ethernet Frame:')
                    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, ethernet_protocol))

                    output.write(TAB_1 + 'IPv4 Packet:\n')
                    output.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}\n'.format(version, header_length, ttl))
                    output.write(TAB_2 + 'Protocol: {}, Source, {}, Target: {}\n'.format(protocol, source, target))

                    print(TAB_1 + 'IPv4 Packet:')
                    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print(TAB_2 + 'Protocol: {}, Source, {}, Target: {}'.format(protocol, source, target))

                    output.write(TAB_1 + 'ICMP Packet:\n')
                    output.write(TAB_2 + 'Type: {}, Code: {}, Checksum: {},\n'.format(icmp_type, code, checksum))
                    output.write(TAB_2 + 'Data:\n')
                    output.write(format_multi_line(DATA_TAB_3, data) + "\n")
                    output.write("-----------------------------------\n\n")
                    output.flush()

                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
                    print("-----------------------------------\n")

            #TCP
                elif protocol == 6:
                    source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

                    output.write('Date and Time: {}\n'.format(DT))
                    output.write('Ethernet Frame:\n')
                    output.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'.format(destination_mac, source_mac, ethernet_protocol))

                    print('Date and Time: {}'.format(DT))
                    print('Ethernet Frame:')
                    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, ethernet_protocol))

                    output.write(TAB_1 + 'IPv4 Packet:\n')
                    output.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}\n'.format(version, header_length, ttl))
                    output.write(TAB_2 + 'Protocol: {}, Source, {}, Target: {}\n'.format(protocol, source, target))

                    print(TAB_1 + 'IPv4 Packet:')
                    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print(TAB_2 + 'Protocol: {}, Source, {}, Target: {}'.format(protocol, source, target))

                    output.write(TAB_1 + 'TCP Segment:\n')
                    output.write(TAB_2 + 'Source Port: {}, Destination Port: {}\n'.format(source_port, destination_port))
                    output.write(TAB_2 + 'Sequence: {}, Acknowledgement: {}\n'.format(sequence, acknowledgment))
                    output.write(TAB_2 + 'Flags:\n')
                    output.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}\n'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    output.write(TAB_2 + 'Data:\n')
                    output.write(format_multi_line(DATA_TAB_3, data) + "\n")
                    output.write("-----------------------------------\n\n")
                    output.flush()

                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(source_port, destination_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgment))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
                    print("-----------------------------------\n")

                #UDP
                elif protocol == 17:
                    source_port, destination_port, length, data = udp_segment(data)

                    output.write('Date and Time: {}\n'.format(DT))
                    output.write('Ethernet Frame:\n')
                    output.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'.format(destination_mac, source_mac, ethernet_protocol))

                    print('Date and Time: {}'.format(DT))
                    print('Ethernet Frame:')
                    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, ethernet_protocol))

                    output.write(TAB_1 + 'IPv4 Packet:\n')
                    output.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}\n'.format(version, header_length, ttl))
                    output.write(TAB_2 + 'Protocol: {}, Source, {}, Target: {}\n'.format(protocol, source, target))

                    print(TAB_1 + 'IPv4 Packet:')
                    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print(TAB_2 + 'Protocol: {}, Source, {}, Target: {}'.format(protocol, source, target))

                    output.write(TAB_1 + 'UDP Segment:\n')
                    output.write(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}\n'.format(source_port, destination_port, length))
                    output.write(TAB_2 + 'Data:\n')
                    output.write(format_multi_line(DATA_TAB_3, data) + "\n")
                    output.write("-----------------------------------\n\n")
                    output.flush

                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(source_port, destination_port, length))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
                    print("-----------------------------------\n")

                else:
                    output.write('Date and Time: {}\n'.format(DT))
                    output.write('Ethernet Frame:\n')
                    output.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'.format(destination_mac, source_mac, ethernet_protocol))

                    print('Date and Time: {}'.format(DT))
                    print('Ethernet Frame:')
                    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, ethernet_protocol))

                    output.write(TAB_1 + 'IPv4 Packet:\n')
                    output.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}\n'.format(version, header_length, ttl))
                    output.write(TAB_2 + 'Protocol: {}, Source, {}, Target: {}\n'.format(protocol, source, target))

                    print(TAB_1 + 'IPv4 Packet:')
                    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print(TAB_2 + 'Protocol: {}, Source, {}, Target: {}'.format(protocol, source, target))
              
                    output.write(TAB_1 + 'Data:\n')
                    output.write(format_multi_line(DATA_TAB_2, data) + "\n")
                    output.write("-----------------------------------\n\n")
                    output.flush()

                    print(TAB_1 + 'Data:')
                    print(format_multi_line(DATA_TAB_2, data))
                    print("-----------------------------------\n")

#Unpack ethernet frame
def format_ethernet_frame(data):
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
    return version, header_length, ttl, protocol, format_ipv4(source), format_ipv4(target), data[header_length:]

#Returns properly formatted IPv4 address
def format_ipv4(addr):
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
    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpacks UDP segment
def udp_segment(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]

#Formats multi-line data
def format_multi_line(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

#Formats data to string for detector
def format_data(string):
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return string

def get_ips():
    try:
        external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
        return external_ip
    
    except:
        s = str(subprocess.check_output(["ifconfig"]))
        s = s.split()

        this_ip = []

        for index, string in enumerate(s):
            if string == "inet":
                this_ip.append(s[index + 1])

        return this_ip
