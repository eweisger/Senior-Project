import ahocorasick
import collections
import pickle
import os
from actions.response import determine_response

def scan_packet(packet):
    if check_whitelist(packet.ipv4.source) == True:
        return

    blacklist_response = check_blacklist(packet.ipv4.source)
    if blacklist_response != False:

        with open('detector/automaton', 'rb') as pickled:
            A = pickle.load(pickled)
            values = []
            
            #Check if automaton is empty (no sigs in sig list)
            if len(A) != 0:
                if packet.ipv4.protocol == "1":
                    for index, value, in A.iter(packet.icmp.data):
                        values.append(value)
                    values = list(dict.fromkeys(values))
                    determine_response(packet, values, "yes", blacklist_response)
                    return

                if packet.ipv4.protocol == "6":
                    for index, value in A.iter(packet.tcp.data):
                        values.append(value)
                    values = list(dict.fromkeys(values))
                    determine_response(packet, values, "yes", blacklist_response)
                    return

                if packet.ipv4.protocol == "17":
                    for index, value in A.iter(packet.udp.data):
                        values.append(value)
                    values = list(dict.fromkeys(values))
                    determine_response(packet, values, "yes", blacklist_response)
                    return

                for index, value in A.iter(packet.data):
                    values.append(value)
                values = list(dict.fromkeys(values))
                determine_response(packet, values, "yes", blacklist_response)
                return

            determine_response(packet, values, blacklisted, blacklist_response)
            return

    with open('detector/automaton', 'rb') as pickled:
        A = pickle.load(pickled)

        #Check if automaton is empty (no sigs in sig list)
        if len(A) != 0:
            values = []

            if packet.ipv4.protocol == "1":
                for index, value, in A.iter(packet.icmp.data.strip()):
                    values.append(value)
                if len(values) != 0:
                    values = list(dict.fromkeys(values))
                    determine_response(packet, values, "no", "none")
                return

            if packet.ipv4.protocol == "6":
                for index, value in A.iter(packet.tcp.data):
                    values.append(value)
                if len(values) != 0:
                    values = list(dict.fromkeys(values))
                    determine_response(packet, values, "no", "none")
                return

            if packet.ipv4.protocol == "17":
                for index, value in A.iter(packet.udp.data):
                    values.append(value)
                if len(values) != 0:
                    values = list(dict.fromkeys(values))
                    determine_response(packet, values, "no", "none")
                return

            for index, value in A.iter(packet.data):
                values.append(value)
            if len(values) != 0:
                values = list(dict.fromkeys(values))
                determine_response(packet, values, "no", "none")
            return


def check_blacklist(ip):
    if os.stat("database/blacklist.txt").st_size != 1:
        with open('database/blacklist.txt', 'r') as blacklist:
            for line in blacklist:
                parsed_line = line.strip()
                parsed_line = line.split(" | ")
                if ip == parsed_line[0]:
                    return parsed_line[1]
    return False


def check_whitelist(ip):
    if os.stat("database/whitelist.txt").st_size != 1:
        with open('database/whitelist.txt', 'r') as whitelist:
            for line in whitelist:
                if ip == line.strip():
                    return True
    return False


def build_signature_database():
    A = ahocorasick.Automaton()

    with open('database/signatures.txt', 'r') as signature_list:
        for index, line in enumerate(signature_list):
            parsed_line = line.strip()
            parsed_line = parsed_line.split(" | ")
            A.add_word(parsed_line[7], index)
    
    A.make_automaton()
    with open('detector/automaton', 'wb') as automaton:
        pickle.dump(A, automaton)
