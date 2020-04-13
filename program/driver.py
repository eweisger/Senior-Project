import subprocess
import multiprocessing
import os
import sys
from signal import signal, SIGINT, SIGTERM

from sensor.sniffer import nids_sniffer, packet_sniffer
from detector.detector import build_signature_database
from database.list_manager import list_manager
from database.alert_manager import alert_manager
from database.sig_manager import sig_manager
from database.sniffer_manager import sniffer_manager

pid = None

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
    global pid
    print("Running Packet Sniffer")
    print("----------------------")
    print("Hit enter to stop the sniffer and exit back to the command prompt\n")
    #packet_sniffer()
    sniffer_process = multiprocessing.Process(target = packet_sniffer)
    sniffer_process.start()
    pid = sniffer_process.pid

def run_NIDS():
    subprocess.call(["ufw", "enable"])
    print("Building Signature Database...")
    build_signature_database()
    print("Running Network Intrusion Detection System")
    print("------------------------------------------")
    print("Type \"stop\" to stop the scanner and exit back to the command prompt\n")
    nids_sniffer()


def help():
    print("General Commands")
    print("----------------")
    print("The packet sniffer will copy all packets to a text file called \"sniffer_output.txt\" in the program's main directory")
    print("   help \t\t prints a list of the commands for the user")
    print("   runsniffer \t\t runs the packet sniffer"+
                         "\n\t\t\t    \"stop\" will stop the packet sniffer")
    print("   runnids \t\t runs the network intrusion detection system"+
                         "\n\t\t\t    \"stop\" will stop the the network intrusion detection system")
    print("   printalerts \t\t print recorded alerts")
    print("   clearalerts \t\t clears all recorded alerts")
    print("   printsniffer \t\t print recorded packet sniffer output")
    print("   clearsniffer \t\t clear all recorded packet sniffer")
    print("   exit \t\t quits the program")

    print("")
    print("Whitelist and Blacklist Commands")
    print("--------------------------------")
    print("The whitelist and blacklist contain a list of IP addresses\n" + 
        "Those in the whitelist never generate an alert, meaning they are ignored and never scanned\n" +
        "Those in the blacklist always generate an alert, meaning they are always reported and still scanned\n")
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
    print("The names associated with signatures are case sensitive, while the signatures themselves and CVEs are not\n" +
          "Names, platforms, services, and ranks cannot contain a \"|\"\n" +
          "CVEs must be of the format cve-yyyy-nnnn with at least 4 digits in the sequence number portion of the id\n" +
          "Signatures must be in the form \\xnn where n is a-f or 0-9\n" +
          "Disclosure dates must be in the form yyyy-mm-dd or yyyy-mm\n")
    print("   checksig signature \t checks if a signature is in the database" +
                         "\n\t\t\t    \"checksig -n name\" searches by signature name" +
                         "\n\t\t\t    \"checksig -c cve\" searches by signature CVE")
    print("   addsig signature \t adds signature to the database, the signature must have a unique name associated with it" +
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


def handler(signal_recieved, frame):
    global pid
    if pid != None:
        os.kill(pid, signal.SIGTERM)
    else:
        print("Exiting program...")
        exit(0)


if __name__ == '__main__':
    signal(SIGINT, handler)
    command_prompt()
