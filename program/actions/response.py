import collections
import subprocess
from database.alert_manager import alert_add

def print_and_store(packet, values, blacklisted):
    if packet.ipv4.protocol == "1":
        alert = (packet.ethernet_frame.date_time + " ||| " + packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " +
                "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "ICMP" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + packet.ipv4.target +
                " ||| " + packet.icmp.icmp_type + " ||| " + packet.icmp.code + " ||| " + packet.icmp.checksum + " ||| ")

        to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Target: {}   ICMP Type: {}   Code: {}   Checksum: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac, packet.ethernet_frame.source_mac, "IPv4", packet.ipv4.ttl, "ICMP", packet.ipv4.source, blacklisted, packet.ipv4.target, packet.icmp.icmp_type, packet.icmp.code, packet.icmp.checksum, packet.ethernet_frame.date_time)

        with open('database/signatures.txt', 'r') as signatures:
            lines = signatures.readlines()
            for value in values:
                line = lines[value].strip()
                parsed_signature = line.split(" | ")
                alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " | " + parsed_signature[6] + " || "

                to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0], 
                        parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[6])

            to_print = to_print + "--------------------------------------------\n"

            if len(values) == 0:
                alert = alert[:-5] #Remove " ||| " and " || " that was accidentally printing in alert list
            else:
                alert = alert[:-4]

            print(to_print)
            alert_add(alert)
            return

    if packet.ipv4.protocol == "6":
        alert = (packet.ethernet_frame.date_time + " ||| " +packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " + 
                "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "TCP" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + packet.ipv4.target +
                " ||| " + packet.tcp.source_port + " ||| " + packet.tcp.destination_port + " ||| " + packet.tcp.sequence + " ||| " + packet.tcp.acknowledgment +
                " ||| " + packet.tcp.flag_urg + " ||| " + packet.tcp.flag_ack + " ||| " + packet.tcp.flag_psh + " ||| " + packet.tcp.flag_rst + " ||| " +
                packet.tcp.flag_syn + " ||| " + packet.tcp.flag_fin + " ||| ")

        to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Target: {}   Source Port: {}   Destination Port: {}   Sequence: {}   Acknowledgment: {}   URG: {}   ACK: {}   PSG: {}   RST: {}   SYN: {}   FIN: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac, packet.ethernet_frame.source_mac, "IPv4", packet.ipv4.ttl, "TCP", packet.ipv4.source, blacklisted, packet.ipv4.target, packet.tcp.source_port, packet.tcp.destination_port, packet.tcp.sequence, packet.tcp.acknowledgment, packet.tcp.flag_urg, packet.tcp.flag_ack, packet.tcp.flag_psh, packet.tcp.flag_rst, packet.tcp.flag_syn, packet.tcp.flag_fin)

        with open('database/signatures.txt', 'r') as signatures:
            lines = signatures.readlines()
            for value in values:
                line = lines[value].strip()
                parsed_signature = line.split(" | ")
                alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " | " + parsed_signature[6] + " || "

                to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0], 
                        parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[6])
            
            to_print = to_print + "--------------------------------------------\n"

            if len(values) == 0:
                alert = alert[:-5]
            else:
                alert = alert[:-4]

            print(to_print)
            alert_add(alert)
            return


    if packet.ipv4.protocol == "17":
        alert = (packet.ethernet_frame.date_time + " ||| " + packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " +
                "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "UDP" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + packet.ipv4.target +
                " ||| " + packet.udp.source_port + " ||| " + packet.udp.destination_port + " ||| ")

        to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Target: {}   Source Port: {}   Destination Port: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac, packet.ethernet_frame.source_mac, "UDP", packet.ipv4.ttl, "ICMP", packet.ipv4.source, blacklisted, packet.ipv4.target, packet.udp.source_port, packet.udp.destination_port)

        with open('database/signatures.txt', 'r') as signatures:
            lines = signatures.readlines()
            for value in values:
                line = lines[value].strip()
                parsed_signature = line.split(" | ")
                alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " | " + parsed_signature[6] + " || "

                to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0], 
                        parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[6])
            
            to_print = to_print + "--------------------------------------------\n"           

            if len(values) == 0:
                alert = alert[:-5]
            else:
                alert = alert[:-4]

            print(to_print)
            alert_add(alert)
            return


    alert = (packet.ethernet_frame.date_time + " ||| " + packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " +
            "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "Other" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + packet.ipv4.target + " ||| ")

    to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Target: {}   Source Port: {}   Destination Port: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac, packet.ethernet_frame.source_mac, "UDP", packet.ipv4.ttl, "ICMP", packet.ipv4.source, blacklisted, packet.ipv4.target, packet.udp.source_port, packet.udp.destination_port)

    with open('database/signatures.txt', 'r') as signatures:
        lines = signatures.readlines()
        for value in values:
            line = lines[value].strip()
            parsed_signature = line.split(" | ")
            alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " || " + parsed_signature[6] + " || "

            to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0], parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[6])
            
        to_print = to_print + "--------------------------------------------\n"

        if len(values) == 0:
            alert = alert[:-5]
        else:
            alert = alert[:-4]

        print(to_print)
        alert_add(alert)

def disconnect():
    print("placeholder")
