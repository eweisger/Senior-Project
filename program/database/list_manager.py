import re
import os

def list_manager(user_input):
    if user_input.casefold() == "printblack":
        blacklist_print()
        return True

    if user_input.casefold() == "printwhite":
        whitelist_print()
        return True

    user_input = user_input.split()

    if user_input[0].casefold() == "checkip":
        check_ip(user_input[1])
        return True

    if user_input[0].casefold() == "addwhite":
        whitelist_add(user_input[1])
        return True

    if user_input[0].casefold() == "addblack":
        blacklist_add(user_input[1])
        return True

    if user_input[0].casefold() == "removeip":
        remove_ip(user_input[1])
        return True

    return False


def whitelist_check(ip):
    if os.stat("database/whitelist.txt").st_size != 1:
        with open("database/whitelist.txt", "r") as whitelist:
            for line in whitelist:
                if ip == line.strip():
                    return True
    return False


def whitelist_add(user_input):
    if len(user_input) == 0:
        print("An IP address or domain name is required\n")
        return

    ip = check_ip_format(user_input)
    if ip[0] == False:
        print("The input \"{}\" is not a proper IP address".format(ip[1]))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255\n")
        return

    if blacklist_check(ip) == True:
        print("The IP address, {}, is already in blacklist\n".format(ip)) 
        return

    if whitelist_check(ip) == True:
        print("The IP address, {}, is already in whitelist\n".format(ip))
        return

    with open("database/whitelist.txt", "a") as whitelist:
        whitelist.write(ip + "\n")


def whitelist_print():
    print("Whitelist")
    print("---------")
    if os.stat("database/whitelist.txt").st_size != 1:
        with open("database/whitelist.txt", "r") as whitelist:
            for line in whitelist:
                print(line.strip())
    print("\n")


def blacklist_check(ip):
    if os.stat("database/blacklist.txt").st_size != 1:
        with open("database/blacklist.txt", "r") as blacklist:
            for line in blacklist:
                if ip == line.strip():
                    return True
    return False


def blacklist_add(user_input):
    if len(user_input) == 0:
        print("An IP address or domain name is required\n")
        return

    ip = check_ip_format(user_input)
    if ip[0] == False:
        print("The input \"{}\" is not a proper IP address".format(ip[1]))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255\n")
        return

    if blacklist_check(ip) == True:
        print("The IP address, {}, is already in blacklist\n".format(ip)) 
        return

    if whitelist_check(ip) == True:
        print("The IP address, {}, is already in whitelist\n".format(ip))
        return

    with open("database/blacklist.txt", "a") as blacklist:
        blacklist.write(ip + "\n")


def blacklist_print():
    print("Blacklist")
    print("---------")
    if os.stat("database/blacklist.txt").st_size != 1:
        with open("database/blacklist.txt", "r") as blacklist:
            for line in blacklist:
                print(line.strip())
    
    print("\n")


def check_ip(user_input):
    if len(user_input) == 0:
        print("An IP address or domain name is required\n")
        return

    ip = check_ip_format(user_input)
    if ip[0] == False:
        print("The input \"{}\" is not a proper IP address".format(ip[1]))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255\n")
        return

    if blacklist_check(ip) == True:
        print("The IP address, {}, is in the blacklist\n".format(ip))
        return

    if whitelist_check(ip) == True:
        print("The IP address, {}, is in the whitelist\n".format(ip))
        return
    
    print("The IP address, {}, is in neither the whitelist or blacklist\n".format(ip))


def remove_ip(user_input):
    if len(user_input) == 0:
        print("An IP address or domain name is required\n")
        return

    ip = check_ip_format(user_input)
    if ip[0] == False:
        print("The input \"{}\" is not a proper IP address".format(ip[1]))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255\n")
        return

    if blacklist_check(ip) == True:
        if os.stat("database/blacklist.txt").st_size != 1:
            with open("database/blacklist.txt", "r+") as blacklist:
                lines = blacklist.readlines()
                blacklist.seek(0)
                blacklist.truncate()

                for line in lines:
                    if line.strip() != ip:
                        blacklist.write(line)
                return

    if whitelist_check(ip) == True:
        if os.stat("database/whitelist.txt").st_size != 1:
            with open("database/whitelist.txt", "r+") as whitelist:
                lines = whitelist.readlines()
                whitelist.seek(0)
                whitelist.truncate()

                for line in lines:
                    if line.strip() != ip:
                        whitelist.write(line)
                return
    
    print("The IP address, {}, is in neither the whitelist or the blacklist\n".format(ip))


def check_ip_format(ip):
    ip = ip.strip()
    re_ip = re.compile("^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$")
    if re_ip.match(ip) == None:
        return False, ip

    return ip
