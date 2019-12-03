#Extraction functions for headers for modularization, belongs to none working version of sniffer

import struct

def extract_ethernet_header(packet):
    #Ethernet header
    header = packet[0][0:14]
    #Unpack ethernet header
    unpacked_header = struct.unpack('!6s6sH', header)
    #Parse ethernet header
    destination_mac = binascii.hexlify(unpacked_header[0])
    source_mac = bianscii.hexlify(unpacked_header[1])
    ethernet_type = bianscii.hexlify(unpacked_header[2])
    #Store elements in dictionary
    ethernet_header = {'Destination MAC Address':destination_mac,
            'Source MAC Address':source_mac,
            'Ethernet Type':ethernet_type}
    return ethernet_header

############################## Ethernet Protocols ##############################
def extract_ip_header(packet):
    #IP header
    header = packet[0][14:34]
    #Unpack IP header
    unpacked_header = struct.unpack('!BBHHHBBH4s4s', header)
    #Parse IP header
    version = unpacked_header[0]
    type_of_service = unpacked_header[1]
    total_length = unpacked_header[2]
    identification = unpacked_header[3]
    fragment_offset = unpacked_header[4]
    time_to_live = unpacked_header[5]
    protocol = unpacked_header[6] 
    checksum = unpacked_header[7]
    source = unpacked_header[8]
    destination = unpacked_header[9]
    options = unpacked_header[10]
    #Store elements in dctionary
    ip_header = {'Protocol Version':version,
            'Type of Service':type_of_service,
            'Total Packet Length':total_length,
            'Identification':identification,
            'Fragmented offset':fragment_offset,
            'Time to Live':time_to_live,
            'Protocol':protocol,
            'Checksum':checksum,
            'Source IP Address':source,
            'Desitnation IP Address':destination,
            'Options':options}
    return ip_header

################################# IP Protocols #################################
def extract_tcp_header(packet):
    #TCP header
    header = packet[0][34:54]
    #Unpack TCP header
    unpacked_header = struct.unpack('!HHLLBBHHH', header)
    #Parse TCP header
    source_port = unpacked_header[0]
    destination_port = unpacked_header[1]
    sequence_number = unpacked_header[2]
    acknowledge_number = unpacked_header[3]
    offset_reserved = unpacked_header[4]
    tcp_flags = unpacked_header[5]
    window_size = unpacked_header[6]
    checksum = unpacked_header[7]
    urgent_pointer = unpacked_header[8]
    options = unpacked_header[9]
    #Store elements in dictionary
    tcp_header = {'Source Port':source_port,
            'Destinartion Port':destination_port,
            'Sequence Number':sequence_number,
            'Acknowledgement Number':acknowledge_number,
            'Data Offset Reserved':offset_reserved,
            'Flags':tcp_flags,
            'Window Size':window_size,
            'Checksum':checksum,
            'Urgent Pointer':urgent_pointer,
            'Options':options}
    return tcp_header

def extract_udp_header(packet):
    #UDP header
    udp_header = packet[0][34:42]
    #Unpack UDP header
    udp_header = struct.unpack('!HHHH', header)
    #Parse UDP header
    source_port = udp_header[0]
    destination_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]
    #Store elements in dictionary
    udp_header = {'Source Port':source_port,
            'Destination Port':destination_port,
            'Total Datagram Length':length,
            'Checksum':checksum}
    return udp_header

def extract_icmp_header(packet):
    #ICMP header
    header = packet[0][34:38]
    #Unpack ICMP header
    unpacked_header = struct.unpack('!BBH', header)
    #Parse ICMP header
    icmp_type = unpacked_header[0]
    code = unpacked_header[1]
    checksum = unpacked_header[2]
    #Store elements in dictionary
    icmp_header = {'Type':icmp_type,
            'Code':code,
            'Checksum':checksum}
    return icmp_header
