import os

def sniffer_manager(user_input):
    if user_input.casefold() == "printsniffer":
        sniffer_output_print()
        return True

    if user_input.casefold() == "clearsniffer":
        sniffer_output_clear()
        return True

    return False


def sniffer_output_print():
    print("Packet Sniffer Output")
    print("---------------------")
    if os.stat("database/sniffer_output.txt").st_size != 1:
        with open("database/sniffer_output.txt", "r") as sniffer_output:
            for line in sniffer_output:
                print(line.strip("\n"))

    print("\n")


def sniffer_output_clear():
    with open("database/sniffer_output.txt", "w+") as sniffer_output:
        sniffer_output.truncate()
