import re

def list_manager(user_input):
    if user_input.casefold() is "printblack":
        blacklist_print()
        return True

    if user_input.casefold() is "printwhite":
        whitelist_print()
        return True

    user_input = user_input.split()

    if user_input[0].casefold() is "checkip":
        check_ip(user_input[1])
        return True

    if user_input[0].casefold() is "addwhite":
        whitelist_add(user_input[1])
        return True

    if user_input[0].casefold() is "addblack":
        blacklist_add(user_input[1])
        return True

    if user_input[0].casefold() is "removeip":
        remove_ip(user_input[1])
        return True

    return False


def whitelist_check(ip):
    with open("whitelist.txt", "r") as whitelist:
        for line in whitelist:
            if ip == line.strip("\n"):
                return True
    return False


def whitelist_add(user_input):
    ip = check_ip_format(user_input)
    if ip is False:
        print("The input {} is not a proper IP address".format(user_input.strip("\n")))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255")
        return

    if blacklist_check(ip) is True:
        print("The IP {} is already in blacklist".format(ip)) 
        return

    if whitelist_check(ip) is True:
        print("The IP {} is already in whitelist".format(ip))
        return

    with open("whitelist.txt", "a") as whitelist:
        whitelist.write(ip + "\n")


def whitelist_print():
    print("Whitelist")
    print("---------")
    with open("whitelist.txt", "r") as whitelist:
        for line in whitelist:
            print(line.strip("\n"))
    print("\n")


def blacklist_check(ip):
    with open("blacklist.txt", "r") as blacklist:
        for line in blacklist:
            if ip == line.strip("\n"):
                return True
    return False


def blacklist_add(user_input):
    ip = check_ip_format(user_input)
    if ip is False:
        print("The input {} is not a proper IP address".format(user_input.strip("\n")))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255")
        return

    if blacklist_check(ip) is True:
        print("The IP {} is already in blacklist".format(ip)) 
        return

    if whitelist_check(ip) is True:
        print("The IP {} is already in whitelist".format(ip))
        return

    with open("blacklist.txt", "a") as blacklist:
        blacklist.write(ip + "\n")


def blacklist_print():
    print("Blacklist")
    print("---------")
    with open("blacklist.txt", "r") as blacklist:
        for line in blacklist:
            print(line.strip("\n"))

    print("\n")


def check_ip(user_input):
    ip = check_ip_format(user_input)
    if ip is False:
        print("The input {} is not a proper IP address".format(user_input.strip("\n")))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255")
        return

    if blacklist_check(ip) is True:
        print("The IP {} is in the blacklist".format(ip))
        return

    if whitelist_check(ip) is True:
        print("The IP {} is in the whitelist".format(ip))
        return
    
    print("The IP {} is in neither the whitelist or blacklist".format(ip))


def remove_ip(user_input):
    ip = check_ip_format(user_input)
    if ip is False:
        print("The input {} is not a proper IP address".format(user_input.strip("\n")))
        print("IP addresses must be in the form n.n.n.n.n where n can be 0-255")
        return

    if blacklist_check(ip) is True:
        with open("blacklist.txt", "w+") as blacklist:
            lines = blacklist.readlines()
            blacklist.seek(0)
            blacklist.truncate()

            for line in lines:
                if line.strip("\n") is not ip:
                    blacklist.write(line)
            return

    if whitelist_check(ip) is True:
        with open("whitelist.txt", "w+") as whitelist:
            lines = whitelist.readlines()
            whitelist.seek(0)

            for line in lines:
                if line.strip("\n") is not ip:
                    whitelist.write(line)
            return
    
    print("The IP {} is in neither the whitelist or the blacklist".format(ip))


def check_ip_format(ip):
    ip = ip.strip("\n")
    re_ip = re.compile("^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$")
    if re_ip.match(ip) is None:
        return False

    return ip


if __name__ == "__main__":
    tests()
