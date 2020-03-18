import re

def sig_manager(user_input):
    if user_input.casefold() is "printsigs":
        print_sigs()
        return True

    user_input = user_input.split()

    if user_input[0].casefold() is "checksig":
        del user_input[0]
        sig_check(user_input)
        return True

    if user_input[0].casefold() is "addsig":
        del user_input[0]
        sig_add(user_input)
        return True

    if user_input[0].casefold() is "removesig":
        del user_input[0]
        sig_remove(user_input)
        return True

    return False

def sig_check(user_input):
    if user_input[0].casefold() is "-n":
        del user_input[0]
        name = " ".join(user_input)
        name = format_name(name)
        if name is False:
            print("The input {} is not a proper name".format(name))
            return

       if check_name(name) is True:
           print("The name {} is in the signature list".format(name))
           return

        print("The name {} is not in the signature list".format(name))
        return

    if user_input[0].casefold() is "-c":
        del user_input[0]
        cve = " ".join(user_input)
        cve = format_cve(cve)
        if cve is False:
            print("The input {} is not a proper CVE".format(cve))
            return

        if check_cve(cve) is True:
            print("The CVE {} is in the signature list".format(cve))
            return

        print("The CVE {} is not in the signature list".format(cve))
        return

    signature = " ".join(user_input)
    signature = format_signature(signature)
    if signature is False:
        print("The input {} is not a proper signature".format(signature))
        return

    if check_sig(signature) is True:
        print("The signature {} is in the signature list".format(signature))
        return

    print("The signature {} is not in the signature list".format(signature))


def sig_add(user_input):
    for string in user_input:
        if string is "-n" or "-p" or "-s" or "-r" or "-d" or "-c":
            break
        signature = " ".join(string)
        user_input.remove(string)

    signature = format_signature(signature)
    if signature is False:
        print("The input {} is not a proper signature".format(signature))
        return

    if check_sig(signature) is True:
        print("The signature {} is already in the signature list".format())
        return

    n = p = s = r = d = c = False
    while user_input is not None:
        if user_input[0].casefold() is "-n":
            if n is True:
                print("You can only have one name")
                return

           del user_input[0]
            for string in user_input:
                if string is "-n" or "-p" or "-s" or "-r" or "-d" or "-c":
                    break
                name = " ".join(string)
                user_input.remove(string)

            name = format_name(name)
            if name is False:
                print("The input {} is not a proper name".format(name))
                return

            if check_name(name) is True:
                print("The name {} is already in the signature list".format(name))
                return
            
            n = True

        if user_input[0].casefold() is "-p":
            if p is True:
                print("You can only have one platform")
                return 

            del user_input[0]
            for string in user_input:
                if string is "-n" or "-p" or "-s" or "-r" or "-d" or "-c":
                    break
                platform = " ".join(string)
                user_input.remove(string)
            
            platform = format_platform(platform)
            if platform is False:
                print("The input {} is not a proper platform".format(platform))
                return

            p = True

        if user_input[0].casefold() is "-s":
            if s is True:
                print("You can only have one service")
                return

            del user_input[0]
            for string in user_input:
                if string is "-n" or "-p" or "-s" or "-r" or "-d" or "-c":
                    break
                service = " ".join(string)
                user_input.remove(string)

            service = format_service(service)
            if service is False:
                print("The input {} is not a proper service".format(service))
                return

            s = True

        if user_input[0].casefold() is "-r":
            if r is True:
                print("You can only have one rank")
                return

            del user_input[0]
            for string in user_input:
                if string is "-n" or "-p" or "-s" or "-r" or "-d" or "-c":
                    break
                rank = " ".join(string)
                user_input.remove(string)

            rank = format_rank(rank)
            if rank is False:
                print("The input {} is not a proper rank".format(rank))
                return

            r = True

        if user_input[0].casefold() is "-d":
            if d is True:
                print("You can only have one disclose date")
                return

            del user_input[0]
            for string in user_input:
                if string is "-n" or "-p" or "-s" or "-r" or "-d" or "-c":
                    break
                disclosed = " ".join(string)
                user_input.remove(string)

            disclosed = format_disclosed(disclosed)
            if disclosed if False:
                print("The input {} is not a proper disclose date".format(disclosed))
                return

            d = True

        if user_input[0].casefold() is "-c":
            if c is True:
                print("You can only have one CVE")
                return

            del user_input[0]
            for string in user_input:
                if string is "-n" or "-p" or "-s" or "-r" or "-d" or "-c":
                    break
                cve = " ".join(string)
                user_input.remove(string)

            cve = format_cve(cve)
            if cve is False:
                print("The input {} us not a proper CVE".format(cve))
                return

            if check_cve(cve) is True:
                print("The CVE {} is already in the signature list".format(cve))
                return

            c = True

    if n is False:
        name = " "

    if p is False:
        platform = " "

    if s is False:
        service = " "

    if r is False:
        rank = " "

    if d is False:
        disclosed = " "

    if c is False:
        cve = " "

    with open("signature_list.txt", "a") as signature_list:
        signature_list.write(name + " | " + platform + " | " + service + " | " + rank + " | " + disclosed + " | " + cve + " | " + signature + "\n")


def sig_remove(user_input):
    if user_input[0].casefold() is "-n":
        del user_input[0]
        name = " ".join(user_input)
        name = format_name(name)
        if name is False:
            print("The input {} is not a proper name".format(name))
            return

        if check_name(name) is True:
            with open("signature_list.txt", "w+") as signature_list:
                lines = signature_list.readlines()
                signature_list.seek(0)
                signature_list.truncate()

                for line in lines:
                    parsed_line = line.strip("\n")
                    parsed_line = parsed_line.split(" | ")
                    if parsed_line[0] is not name:
                        signature_list.write(line)
                return

        print("The name {} is not in the signature list".format(name))
        return

    if user_input[0].casefold() is "-c":
        del user_input[0]
        cve = " ".join(user_input)
        cve = format_cve(cve)
        if cve is False:
            print("The input {} is not a proper CVE".format(cve))
            return

        if check_cve(cve) is True:
            with open("signature_list.txt", "w+") as signature_list:
                lines = signature_list.readlines()
                signature_list.seek(0)
                signature_list.truncate()

                for line in lines:
                    parsed_line = line.strip("\n")
                    prased_line = parsed_line.split(" | ")
                    if parsed_line[5] is not cve:
                        signature_list.write(line)
                return

        print("The CVE {} is not in the signature list".format(cve))
        return

    signature = " ".join(user_input)
    signature = format_signature(signature)
    if signature is False:
        print("The input {} is not a proper signature".format(signature))
        return

    if check_sig(signature) is True:
        with open("signature_list.txt", "w+") as signature_list:
            lines = signature_list.readlines()
            signature_list.seek(0)
            signature_list.truncate()

            for line in lines:
                parsed_line = line.strip("\n")
                parsed_line = parsed_line.split(" | ")
                if parsed_line[6] is not signature:
                    signature_list.write(line)
            return

    print("The signature {} is not in the signature list".format(signature))


def print_sigs():
    print("\n")
    print("Signatures")
    print("----------")
    with open("siglist.txt", "r") as siglist:
        for line in siglist:
            parsed_line = line.strip("\n")
            parsed_line = parsed_line.split(" | ")
            print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}\n"
                    + "Signature: {}\n".format(parsed_line[0], parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4], parsed_line[5], parsed_line[6]))
    print("\n")


def check_sig(signature):
    with open("signature_list.txt", "r") as signature_list:
        for line in signature_list:
            parsed_line = line.strip("\n")
            parsed_line = parsed_line.split(" | ")
            if signature is parsed_line[6]:
                return True    
    return False


def check_name(name):
    with open("signature_list.txt", "r") as signature_list:
        for line in signature_list:
            parsed_line = line.strip("\n")
            parsed_line = parsed_line.split(" | ")
            if name is parsed_line[0]:
                return True
    return False


def check_cve(cve):
    with open("signature_list.txt", "r") as signature_list:
        for line in signature_list:
            parsed_line = line.strip("\n")
            parsed_line = parsed_line.split(" | ")
            if cve is parsed_line[5]:
                return True
    return False


def format_sig(signature):
    signature = signature.strip("\n")
    re_sig = re.complie("^(\\x([0-9]|[a-f])([0-9]|[a-f]))+$")
    if re_sig.match(signature) is None:
        return False

    return signature


def format_disclosed(disclosed):
    disclosed = disclosed.strip("\n")
    re_disclosed = re.complie("^([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])|([0-9][0-9][0-9][0-9]-[0-9][0-9])$")
    if re_disclosed.match(disclosed) is None:
        return False

    return disclosed


def format_cve(cve):
    cve = cve.strip("\n")
    re_cve = re.complie("^cve-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]+$")
    if re_cve.match(cve) is None:
        return False

    return cve


def format_name(name):
    name = name.strip("\n")
    re_name = re.complie("^(\S+)|(\S+( \S+)+)$")
    if re_name.match(name) is None:
        return False

    return name


def format_platform(platform):
    platform = platform.strip("\n")
    re_platform = re.complie("^(\S+)|(\S+( \S+)+)$")
    if re_platform.match(platform) is None:
        return False

    return platform


def format_service(service):
    service = service.strip("\n")
    service = service.casefold()
    re_service = re.complie("^(\S+)|(\S+( \S+)+)$")
    if re_service.match(service) is None:
        return False

    return service


def format_rank(rank):
    rank = rank.strip("\n")
    rank = rank.casefold()
    re_rank = re.complie("^excellent|great|good|normal|average|low|manual$")
    if re_rank.match(rank) is None:
        return False

    return rank

