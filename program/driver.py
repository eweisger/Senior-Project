#from sensor.sniffer import sniffer
#from databse.database import build_database
#from program.database.list_manager import list_manager

def command_prompt():
    welcome_message()
    
    user_input = "NULL"
    while user_input.casefold() is not "exit":
        user_input = input(">>")
    
        if user_input.casefold() is "help":
            help()

        elif user_input.casefold() is "run":
            run()


def welcome_message():
    with open("welcome_image.txt") as image:
        for line in image:
            print(line.strip("\n"))

    print("                                    ___ _                ")
    print("| | _  |  _  _ __  _    _|_ _    |\| | | \|_| _    __  _|")
    print("|^|(/_ | (_ (_)|||(/_    |_(_)   | |_|_|_/| |(_)|_|| |(_|")
    print("Type \"help\" for a list of commands or \"exit\" to exit")


def help():
    print("\n")
    print("General Commands")
    print("----------------")
    print("\t help \t\t\t prints a list of the commands for the user")
    #print("\t run \t\t\t runs the main program")
    print("\t printalerts \t\t\t print recorded alerts")
    print("\t clearalerts \t\t\ clears all recorded alerts")
    print("\t exit \t\t\t quits the program")

    print("\n")
    print("Whitelist and Blacklist Commands")
    print("--------------------------------")
    print("The whitelist and blacklist contain a list of IP addresses." + 
        " Those in the whitelist never generate an alert, meaning nothing will be reported if a signature is detected by any of the IP addresses in this list." +
        " Those in the blacklist always generate an alert, meaning every packet recieved by any of the IP addresses in this list will be reported.\n")
    print("\t checkip ip \t\t checks if ip is in whitelist or blacklist")
    print("\t addwhite ip \t\t adds ip to whitelist")
    print("\t addblack ip \t\t adds ip to blacklist")
    print("\t removeip ip \t\t removes ip from whitelist or blacklist")
    print("\t printblack \t\t prints the current blacklist")
    print("\t printwhite \t\t prints the current whitelist")

    print("\n")
    print("Signature Commands")
    print("------------------")
    print("\t checksig signature \t\t checks if a signature is in the database\n")
    print("\t addsig signature \t\t adds signature to the database\n")
    print("\t removesig signature \t\t removes signature from the database\n")
    print("\t printsigs \t\t prints the signature database\n")


def run():
    #build_database()
    #sniffer()
    print("run")



if __name__ == '__main__':
    command_prompt()
