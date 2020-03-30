#from sensor.sniffer import sniffer
#from databse.database import build_database
#from program.database.list_manager import list_manager

def command_prompt():
    welcome_message()
    
    #If files don't exist create them
    open("database/alerts.txt", "a")
    open("database/signatures.txt", "a")
    open("database/whitelist.txt", "a")
    open("database/blacklist.txt", "a")
    
    user_input = ""
    while user_input.casefold() != "exit":
        user_input = input(">>")
    
        if user_input.casefold() == "help":
            help()


def welcome_message():
    with open("welcome_image.txt") as image:
        for line in image:
            print(line.strip("\n"))

    print("                                    ___ _                ")
    print("| | _  |  _  _ __  _    _|_ _    |\| | | \|_| _    __  _|")
    print("|^|(/_ | (_ (_)|||(/_    |_(_)   | |_|_|_/| |(_)|_|| |(_|")
    print("Type \"help\" for a list of commands or \"exit\" to exit")


def run_sniffer():
    print("Running Packet Sniffer")
    print("----------------------")
    print("Type \"stop\" to stop the sniffer and exit back to the command prompt")
    user_input = None
    while user_input.casefold() != "stop":
        user_input = input("Scanner>>")
        packet_sniffer()


def run_NIDS():
    print("Building Signature Database...")
    build_signature_database()
    print("Running Network Intrusion Detection System")
    print("------------------------------------------")
    print("Type \"stop\" to stop the scanner and exit back to the command prompt")
    user_input = None
    while user_input.casefold() != "stop":
        user_input =  input("Scanner >>")
        nids_sniffer()


def help():
    print("General Commands")
    print("----------------")
    print("   help \t\t prints a list of the commands for the user")
    print("   runsniffer \t\t runs the packet sniffer"+
                         "\n\t\t\t    \"stop\" will stop the packet sniffer")
    print("   runnids \t\t runs the network intrusion detection system"+
                         "\n\t\t\t    \"stop\" will stop the the network intrusion detection system")
    print("   printalerts \t\t print recorded alerts")
    print("   clearalerts \t\t clears all recorded alerts")
    print("   exit \t\t quits the program")

    print("")
    print("Whitelist and Blacklist Commands")
    print("--------------------------------")
    print("The whitelist and blacklist contain a list of IP addresses\n" + 
        "Those in the whitelist never generate an alert, meaning they are ignored and never scanned\n" +
        "Those in the blacklist always generate an alert, meaning they are always reported and still scanned\n")
    print("   checkip ip \t\t checks if ip is in whitelist or blacklist")
    print("   addwhite ip \t\t adds ip to whitelist")
    print("   addblack ip \t\t adds ip to blacklist")
    print("   removeip ip \t\t removes ip from whitelist or blacklist")
    print("   printblack \t\t prints the current blacklist")
    print("   printwhite \t\t prints the current whitelist")

    print("")
    print("Signature Commands")
    print("------------------")
    print("   checksig signature \t checks if a signature is in the database" +
                         "\n\t\t\t    \"checksig -n name\" searches by signature name" +
                         "\n\t\t\t    \"checksig -c cve\" searches by signature CVE")
    print("   addsig signature \t adds signature to the database, the signature must have a unique name associated with it" +
                         "\n\t\t\t    Flag \"-n name\" adds name" +
                         "\n\t\t\t    Optional flag \"-p platform\" adds platform" +
                         "\n\t\t\t    Optional flag \"-s service\" adds service" +
                         "\n\t\t\t    Optional flag \"-r rank\" adds rank" +
                         "\n\t\t\t    Optional flag \"-d date\" adds date" +
                         "\n\t\t\t    Optional flag \"-c cve\" adds CVE")
    print("   removesig signature \t removes signature from the database" +
                        "\n\t\t\t    \"removesig -n name\" removes signature by name" +
                        "\n\t\t\t    \"removesig -c cve\" removes signature by CVE")
    print("   printsigs \t\t prints the signature database\n")


if __name__ == '__main__':
    command_prompt()
