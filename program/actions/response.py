import time
import collections
import subprocess
import multiprocessing
from database.alert_manager import alert_add

def determine_response(packet, values, blacklisted, blacklist_response):
    current_response = blacklist_response.strip()

    with open("database/signatures.txt", "r") as signatures:
        lines = signatures.readlines()
        parsed_signatures = []
        for value in values:
            line = lines[value].strip()
            parsed_signature = line.split(" | ")
            parsed_signatures.append(parsed_signature)

            if parsed_signature[6] != "none":
                parsed_response = parsed_signature[6].split()
                parsed_response = parsed_response[1].split(":")

                sum_response = int(parsed_response[0])*60*60 + int(parsed_response[1])*60 + int(parsed_response[2])

                if current_response != "none":
                    parsed_current_response = current_response.split()
                    parsed_current_response = current_response.split(":")

                    sum_current_response = int(parsed_current_response[0])*60*60 + int(parsed_current_response[1])*60 + int(parsed_current_response[2])

                    if int(sum_response) > int(sum_current_response):
                        current_response = parsed_signature[6]

                else:
                    current_response = parsed_signature[6]
 
    record(packet, parsed_signatures, blacklisted, current_response.strip())
    if current_response.strip() != "none":
        if packet.ipv4.protocol == "1":
            block_process = multiprocessing.Process(target = block_icmp, args = (packet, current_response, ))
            block_process.start()
            block_process.join()
            return

        if packet.ipv4.protocol == "6":
            block_process = multiprocessing.Process(target = block_tcp, args = (packet, current_response, ))
            block_process.start()
            block_process.join()
            return

        if packet.ipv4.protocol == "17":
            block_process = multiprocessing.Process(target = block_udp, args = (packet, current_response, ))
            block_process.start()
            block_process.join()
            return
            

def record(packet, parsed_signatures, blacklisted, response_taken):
    if packet.ipv4.protocol == "1":
        alert = (packet.ethernet_frame.date_time + " ||| " + packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " +
                "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "ICMP" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + " ||| " + response_taken +
                packet.ipv4.target + " ||| " + packet.icmp.icmp_type + " ||| " + packet.icmp.code + " ||| " + packet.icmp.checksum + " ||| ")

        to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Response Taken: {}   Target: {}   ICMP Type: {}   Code: {}   Checksum: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac, packet.ethernet_frame.source_mac, "IPv4", packet.ipv4.ttl, "ICMP", packet.ipv4.source, blacklisted, response_taken, packet.ipv4.target, packet.icmp.icmp_type, packet.icmp.code, packet.icmp.checksum)

        for parsed_signature in parsed_signatures:
            alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " | " + parsed_signature[7] + " || "

            to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0], 
                        parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[7])

        to_print = to_print + "--------------------------------------------\n"

        if len(parsed_signatures) == 0:
            alert = alert[:-5] #Remove " ||| " or " || " that was accidentally printing in alert list
        else:
            alert = alert[:-4]

        print(to_print)
        alert_add(alert)
        return

    if packet.ipv4.protocol == "6":
        alert = (packet.ethernet_frame.date_time + " ||| " +packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " + 
                "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "TCP" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + response_taken + 
                " ||| " + packet.ipv4.target + " ||| " + packet.tcp.source_port + " ||| " + packet.tcp.destination_port + " ||| " + packet.tcp.sequence + 
                " ||| " + packet.tcp.acknowledgment + " ||| " + packet.tcp.flag_urg + " ||| " + packet.tcp.flag_ack + " ||| " + packet.tcp.flag_psh + 
                " ||| " + packet.tcp.flag_rst + " ||| " + packet.tcp.flag_syn + " ||| " + packet.tcp.flag_fin + " ||| ")

        to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Response Taken: {}   Target: {}   Source Port: {}   Destination Port: {}   Sequence: {}   Acknowledgment: {}   URG: {}   ACK: {}   PSG: {}   RST: {}   SYN: {}   FIN: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac, packet.ethernet_frame.source_mac, "IPv4", packet.ipv4.ttl, "TCP", packet.ipv4.source, blacklisted, response_taken, packet.ipv4.target, packet.tcp.source_port, packet.tcp.destination_port, packet.tcp.sequence, packet.tcp.acknowledgment, packet.tcp.flag_urg, packet.tcp.flag_ack, packet.tcp.flag_psh, packet.tcp.flag_rst, packet.tcp.flag_syn, packet.tcp.flag_fin)

        for parsed_signature in parsed_signatures:
            alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " | " + parsed_signature[7] + " || "
            to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0], 
                        parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[7])
        to_print = to_print + "--------------------------------------------\n"

        if len(parsed_signatures) == 0:
            alert = alert[:-5]
        else:
            alert = alert[:-4]

        print(to_print)
        alert_add(alert)
        return


    if packet.ipv4.protocol == "17":
        alert = (packet.ethernet_frame.date_time + " ||| " + packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " +
                "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "UDP" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + response_taken + 
                " ||| " + packet.ipv4.target + " ||| " + packet.udp.source_port + " ||| " + packet.udp.destination_port + " ||| ")

        to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Response Taken: {}   Target: {}   Source Port: {}   Destination Port: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac,
                packet.ethernet_frame.source_mac, "UDP", packet.ipv4.ttl, "UDP", packet.ipv4.source, blacklisted, response_taken, packet.ipv4.target,
                packet.udp.source_port, packet.udp.destination_port)

        for parsed_signature in parsed_signatures:
            alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " | " + parsed_signature[7] + " || "

            to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0], 
                        parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[7])
            
        to_print = to_print + "--------------------------------------------\n"           

        if len(parsed_signatures) == 0:
            alert = alert[:-5]
        else:
            alert = alert[:-4]

        print(to_print)
        alert_add(alert)
        return


    alert = (packet.ethernet_frame.date_time + " ||| " + packet.ethernet_frame.destination_mac + " ||| " + packet.ethernet_frame.source_mac + " ||| " +
            "IPv4" + " ||| " + packet.ipv4.ttl + " ||| " + "Other" + " ||| " + packet.ipv4.source + " ||| " + blacklisted + " ||| " + response_taken +
            " ||| " + packet.ipv4.target + " ||| ")

    to_print = "Date and Time: {}   Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Response Taken: {}   Target: {}\n".format(packet.ethernet_frame.date_time, packet.ethernet_frame.destination_mac, packet.ethernet_frame.source_mac,
            "IPv4", packet.ipv4.ttl, "Other", packet.ipv4.source, blacklisted, response_taken, packet.ipv4.target)

    for parsed_signature in parsed_signatures:
        alert = alert + parsed_signature[0] + " | " + parsed_signature[1] + " | " + parsed_signature[2] + " | " + parsed_signature[3] + " | " + parsed_signature[4] + " | " + parsed_signature[5] + " || " + parsed_signature[7] + " || "

        to_print = to_print + "Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\nSignature: {}\n".format(parsed_signature[0],
                parsed_signature[1], parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5], parsed_signature[7])
            
    to_print = to_print + "--------------------------------------------\n"

    if len(parsed_signatures) == 0:
        alert = alert[:-5]
    else:
        alert = alert[:-4]

    print(to_print)
    alert_add(alert)


def block_icmp(packet, response):
    parsed_response = response.split()
    parsed_response = parsed_response[1].split(":")
    sleep_time = int(parsed_response[0])*60*60 + int(parsed_response[1])*60 + int(parsed_response[2])

    subprocess.call(["ufw", "deny", "from", packet.ipv4.source])

    time.sleep(sleep_time)

    subprocess.call(["ufw", "delete", "deny", "from", packet.ipv4.source])


def block_tcp(packet, response):
    parsed_response = response.split()
    parsed_response = parsed_response[1].split(":")
    sleep_time = int(parsed_response[0])*60*60 + int(parsed_response[1])*60 + int(parsed_response[2])

    subprocess.call(["ufw", "deny", "from", packet.ipv4.source, "port", packet.tcp.source_port])

    time.sleep(sleep_time)

    subprocess.call(["ufw", "delete", "deny", "from", packet.ipv4.source, "port", packet.tcp.source_port])

def block_udp():
    parsed_response = response.split()
    parsed_response = parsed_response[1].split(":")
    sleep_time = int(parsed_response[0])*60*60 + int(parsed_response[1])*60 + int(parsed_response[2])

    subprocess.call(["ufw", "deny", "from", packet.ipv4.source, "port", packet.udp.source_port])

    time.sleep(sleep_time)

    subprocess.call(["ufw", "delete", "deny", "from", packet.ipv4.source, "port", packet.udp.source_port])


