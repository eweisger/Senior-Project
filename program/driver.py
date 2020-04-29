import subprocess
import multiprocessing
import os
import sys

from sensor.sniffer import nids_sniffer, packet_sniffer
from detector.detector import build_signature_database
from database.list_manager import list_manager
from database.alert_manager import alert_manager
from database.sig_manager import sig_manager
from database.sniffer_manager import sniffer_manager

def command_prompt():
    welcome_message()
    
    #If files don't exist create them
    a = open("database/alerts.txt", "a")
    a.close()
    s = open("database/signatures.txt", "a")
    s.close()
    w = open("database/whitelist.txt", "a")
    w.close()
    b = open("database/blacklist.txt", "a")
    b.close()
    c = open("database/sniffer_output.txt", "a")
    c.close()
    
    user_input = ""
    while user_input.casefold() != "exit":
        user_input = input(">>")
    
        if user_input.casefold() == "help":
            help()

        elif user_input.casefold() == "runsniffer":
            run_sniffer()

        elif user_input.casefold() == "runnids":
            run_NIDS()

        elif list_manager(user_input) == True:
            pass

        elif sig_manager(user_input) == True:
            pass

        elif alert_manager(user_input) == True:
            pass

        elif sniffer_manager(user_input) == True:
            pass

        elif user_input.casefold() != "exit":
            print("The input \"{}\" is not a command\n".format(user_input))


def welcome_message():
    with open("welcome_image.txt") as image:
        for line in image:
            print(line.rstrip())

    print("                                    ___ _                ")
    print("| | _  |  _  _ __  _    _|_ _    |\| | | \|_| _    __  _|")
    print("|^|(/_ | (_ (_)|||(/_    |_(_)   | |_|_|_/| |(_)|_|| |(_|")
    print("Type \"help\" for a list of commands or \"exit\" to exit")


def run_sniffer():
    print("Running Packet Sniffer")
    print("----------------------")
    print("Press \"enter\" to stop the sniffer and exit back to the command prompt\n")
    sniffer_process = multiprocessing.Process(target = packet_sniffer)
    sniffer_process.start()

    user_input = input("")

    print("Stopping packet sniffer")
    sniffer_process.terminate()

def run_NIDS():
    subprocess.call(["ufw", "enable"])
    print("Building Signature Database...")
    build_signature_database()
    print("Running Network Intrusion Detection System")
    print("------------------------------------------")
    print("Press \"enter\" to stop the scanner and exit back to the command prompt\n")
    nids_process = multiprocessing.Process(target = nids_sniffer)
    nids_process.start()

    user_input = input("")

    print("Stopping NIDS")
    nids_process.terminate()


def help():
    print("General Commands")
    print("----------------")
    print("The packet sniffer will copy all packets to a text file called \"sniffer_output.txt\" in the program's main directory")
    print("   help \t\t prints a list of the commands for the user")
    print("   runsniffer \t\t runs the packet sniffer"+
                         "\n\t\t\t    Press enter to stop the packet sniffer")
    print("   runnids \t\t runs the network intrusion detection system"+
                         "\n\t\t\t    Press enter to stop the the network intrusion detection system")
    print("   printalerts \t\t print recorded alerts")
    print("   clearalerts \t\t clears all recorded alerts")
    print("   printsniffer \t\t print recorded packet sniffer output")
    print("   clearsniffer \t\t clear all recorded packet sniffer")
    print("   exit \t\t quits the program")

    print("")
    print("Whitelist and Blacklist Commands")
    print("--------------------------------")
    print("The whitelist and blacklist contain a list of IP addresses. Those in the\n"
        "whitelist never generate an alert, meaning they are ignored and never scanned.\n" +
        "Those in the blacklist always generate an alert, meaning they are always\n" +
        "reported, regardless of whether or not a matching signature is found, and\n" +
        "are always scanned. Ip addresses in the blacklist include a response for when\n" +
        "a packet originating from the IP address is detected, which by default is\n" +
        "\"none\". The response can be specified with the optional flag \"-re response\".\n")
    print("   checkip ip \t\t checks if ip is in whitelist or blacklist")
    print("   addwhite ip \t\t adds ip to whitelist")
    print("   addblack ip \t\t adds ip to blacklist" +
                        "\n\t\t\t     Optional flag \"-re response\" specifies response")
    print("   removeip ip \t\t removes ip from whitelist or blacklist")
    print("   printblack \t\t prints the current blacklist")
    print("   printwhite \t\t prints the current whitelist")

    print("")
    print("Signature Commands")
    print("------------------")
    print("The signature list contains the signatures to be check against each packet. Each\n" +
        "signature must have a unique name associated with it and can optionally include a\n" +
        "platform, service, threat rank, disclosure date, a unique CVE ID. Each signature\n" +
        "includes a response for when it is detected, which by default is \"none\". The response\n" +
        "can be specified with the optional flag \"-re response\". Signature names are case\n" +
        "sensitive, signature names, platforms, services, and ranks cannot contain a \"|\",\n" +
        "and CVEs must be of the format cve-yyyy-nnnn with at least 4 digits in the sequence\n" +
        "number portion of the id\n, Signatures must be in the form \\xnn where n is a-f or 0-9\n" +
        "Disclosure dates must be in the form yyyy-mm-dd or yyyy-mm\n")
    print("   checksig signature \t checks if a signature is in the database" +
                         "\n\t\t\t    \"checksig -n name\" searches by signature name" +
                         "\n\t\t\t    \"checksig -c cve\" searches by signature CVE")
    print("   addsig signature \t adds signature to the database, the signature must have a\n" +
                         "\t\t\t unique name associated with it" +
                         "\n\t\t\t    Flag \"-n name\" adds name" +
                         "\n\t\t\t    Optional flag \"-p platform\" adds platform" +
                         "\n\t\t\t    Optional flag \"-s service\" adds service" +
                         "\n\t\t\t    Optional flag \"-ra rank\" adds rank" +
                         "\n\t\t\t    Optional flag \"-d date\" adds date" +
                         "\n\t\t\t    Optional flag \"-c cve\" adds CVE" +
                         "\n\t\t\t    Optional flag \"-re respone\" specifies response")
    print("   removesig signature \t removes signature from the database" +
                        "\n\t\t\t    \"removesig -n name\" removes signature by name" +
                        "\n\t\t\t    \"removesig -c cve\" removes signature by CVE")
    print("   printsigs \t\t prints the signature database\n")

if __name__ == '__main__':
    command_prompt()
