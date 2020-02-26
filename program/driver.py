from sensor.sniffer import sniffer

def command_prompt():
    welcome_message()
    
    user_input = "NULL"
    while user_input != "exit":
        user_input = input(">>")
    
        if user_input == "help":
            help()

        if user_input == "run":
            run()

def run():
    sniffer()


def help():
    print("\t help \t\t prints a list of the commands for the user")
    print("\t run \t\t runs the main program")
    print("\t exit \t\t quits the program")


def welcome_message():
    print("Welcome to NIDHound")
    print("Please type \"help\" for a list of commands")


if __name__ == '__main__':
    command_prompt()
