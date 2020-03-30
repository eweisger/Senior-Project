import ahocorasick
import collections
import pickle

def scan_packet(packet):
    if check_whitelist(packet.ipv4.source) is True:
        return

    if check_blacklist(packet.ipv4.source) is True:
        blacklisted = "Yes"

        with open('automaton.txt', 'ar') as pickled:
            A = pickle.load(pickled)
            values = []

            if packet.ipv4.protocol is 1:
                for index, value, in A.iter(packet.icmp.data):
                    values.append(value)
                print_and_store(packet, values, blacklisted)
                return

            if packet.ipv4.protocol is 6:
                for index, value in A.iter(packet.tcp.data):
                    values.append(value)
                print_and_store(packet, values, blacklisted)
                return

            if packet.ipv4.protocol is 17:
                for index, value in A.iter(packet.udp.data):
                    values.append(value)
                print_and_store(packet, values, blacklisted)
                return

            for index, value in A.iter(packet.data):
                values.append(value)
            print_and_store(packet, values, blacklisted)
            return

    blacklisted = "No"
    with open('automaton.txt', 'ar') as pickled:
        A = pickle.load(pickled)
        values = []

        if packet.ipv4.protocol is 1:
            for index, value, in A.iter(packet.icmp.data):
                values.append(value)
            if values is not None:
                print_and_store(packet, values, blacklisted)
            return

        if packet.ipv4.protocol is 6:
            for index, value in A.iter(packet.tcp.data):
                values.append(value)
            if values is not None:
                print_and_store(packet, values, blacklisted)
            return

        if packet.ipv4.protocol is 17:
            for index, value in A.iter(packet.udp.data):
                values.append(value)
            if values is not None:
                print_and_store(packet, values, blacklisted)
            return

        for index, value in A.iter(packet.data):
            values.append(value)
        if values in not None:
            print_and_store(packet, values, blacklisted)
        return


def check_blacklist(packet):
    with open('../database/blacklist.txt', 'r') as blacklist:
        for line in blacklist:
            if packet.ipv4.source is line.strip('\n'):
                return True
    return False


def check_whitelist(packet):
    with open('../database/whitelist.txt', 'r') as whitelist:
        for line in whitelist:
            if packet.ipv4.source is line.strip('\n'):
                return True
    return False


def build_signature_database():
    A = ahocorasick.Automaton()

    with open('../database/signatures.txt', 'r') as signature_list:
        for index, line in enumerate(signature_list):
            parsed_line = line.strip("\n")
            parsed_line = parsed_line.split(" | ")
            A.add_word(parsed_line, index)
    
    A.make_automaton()
    with open('automaton.txt', 'w') as automaton:
        pickle.dump(A, automaton)

