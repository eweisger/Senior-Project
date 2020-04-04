import collections
import os

def alert_manager(user_input):
    if user_input.casefold() == "printalerts":
        alert_print()
        return True

    if user_input.casefold() == "clearalerts":
        alert_clear()
        return True

    return False


def alert_add(alert):
    with open("alerts.txt", "a") as alerts:
        alerts.write(alert + "\n")


def alert_clear():
    with open("alerts.txt", "w+") as alerts:
        alerts.truncate()


def alert_print():
    print("Alerts")
    print("------")
    if os.stat("alerts.txt").st_size != 1:
        with open("alerts.txt", "r") as alerts:
            for line in alerts:
                parsed_line = line.strip()
                parsed_line = parsed_line.split(" ||| ")
        
                if parsed_line[4] == "ICMP":
                    print("Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Target: {}" +
                      "   ICMP Type: {}   Code: {}   Checksum: {}".format(parsed_line[0], parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4], 
                      parsed_line[5], parsed_line[6], parsed_line[7], parsed_line[8], parsed_line[9], parsed_line[10]))
                
                    if parsed_line[11] != "":
                        signatures = parsed_line[11].split(" || ")
                        for signature in signatures:
                            parsed_signature = parsed_line.split(" | ")
                            print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}".format(parsed_signature[0], parsed_signature[1], 
                              parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5]))
                    print("--------------------------------------------\n")

            
                elif parsed_line[4] == "TCP":
                    print("Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Target: {}" +
                      "   Source Port: {}   Destination Port: {}   Sequence: {}   Acknowledgment: {}   URG: {}   ACK: {}   PSG: {}   RST: {}   SYN: {}" +
                      "   FIN: {}".format(parsed_line[0], parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4], parsed_line[5], parsed_line[6], 
                      parsed_line[7], parsed_line[8], parsed_line[9], parsed_line[10], parsed_line[11], parsed_line[12], parsed_line[13], parsed_line[14], 
                      parsed_line[15], parsed_line[16], parsed_line[17]))
                
                    if parsed_line[18] != "":
                        signatures = parsed_line[18].split(" || ")
                        for signature in signatures:
                            parsed_signature = parsed_line.split(" | ")
                            print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}".format(parsed_signature[0], parsed_signature[1], 
                              parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5]))
                    print("--------------------------------------------\n")
          
                elif parsed_line[4] == "UDP":
                    print("Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}   Target: {}" +
                      "   Source Port: {}   Destination Port: {}".format(parsed_line[0], parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4],
                      parsed_line[5], parsed_line[6], parsed_line[7], parsed_line[8], parsed_line[9]))
                
                    if parsed_line[10] != "":
                        signatures = parsed_line[10].split(" || ")
                        for signature in signatures:
                            parsed_signature = parsed_line.split(" | ")
                            print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}".format(parsed_signature[0], parsed_signature[1], 
                              parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5]))
                    print("--------------------------------------------\n")
           
                else:
                    print("Destination Mac: {}   Source Mac: {}   Ethernet Protocol: {}   TTL: {}   Protocol: {}   Source: {}   Blacklisted: {}" +
                       "   Target: {}".format(parsed_line[0], parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4], parsed_line[5], 
                       parsed_line[6], parsed_line[7]))
                
                    if parsed_line[8] != "":
                        signatures = parsed_line[8].split(" || ")
                        for signature in signatures:
                            parsed_signature = parsed_line.split(" | ")
                            print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}".format(parsed_signature[0], parsed_signature[1], 
                              parsed_signature[2], parsed_signature[3], parsed_signature[4], parsed_signature[5]))
                    print("--------------------------------------------\n")
    print("\n")
