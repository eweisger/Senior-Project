import re
import os

def sig_manager(user_input):
    if user_input.casefold() == "printsigs":
        sig_print()
        return True

    user_input = user_input.split()

    if user_input[0].casefold() == "checksig":
        user_input = user_input[1:]
        sig_check(user_input)
        return True

    if user_input[0].casefold() == "addsig":
        user_input = user_input[1:]
        sig_add(user_input)
        return True

    if user_input[0].casefold() == "removesig":
        user_input = user_input[1:]
        sig_remove(user_input)
        return True

    return False


def sig_check(user_input):
    if len(user_input) == 0:
        print("A signautre, name, or CVE is required\n")
        return False

    if user_input[0].casefold() == "-n":
        user_input = user_input[1:]
        name = " ".join(user_input)
        name = format_name(name)
        if name[0] == False:
            print("The input \"{}\" is not a proper name".format(name[1]))
            print("Names cannot begin with a space or contain a \"|\"\n")
            return False

        #Check if file is empty to avoid index out of bounds error
        if os.stat("database/signatures.txt").st_size != 1:
            with open("database/signatures.txt", "r") as signatures:
                for line in signatures:
                    parsed_line = line.strip()
                    parsed_line = parsed_line.split(" | ")
                    if name == parsed_line[0]:
                        print("The name, {}, is in the signature list".format(name))
                        print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}   Response: {}\nSignature: {}\n".format(parsed_line[0],
                            parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4], parsed_line[5], parsed_line[6], parsed_line[7]))
                        return

        print("The name, {}, is not in the signature list\n".format(name))
        return

    if user_input[0].casefold() == "-c":
        user_input = user_input[1:]
        cve = " ".join(user_input)
        cve = format_cve(cve)
        if cve[0] == False:
            print("The input \"{}\" is not a proper CVE".format(cve[1]))
            print("CVEs must be in the format cve-yyyy-nnnn with at least 4 digits in the sequence number portion of the id\n")
            return False
    
        #check if file is empty to avoid index out of bounds error
        if os.stat("database/signatures.txt").st_size != 1:
            with open("database/signatures.txt", "r") as signatures:
                for line in signatures:
                    parsed_line = line.strip()
                    parsed_line = parsed_line.split(" | ")
                    if cve == parsed_line[5]:
                        print("The CVE, {}, is in the signature list".format(cve))
                        print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}   Response: {}\nSignature: {}\n".format(parsed_line[0],
                            parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4], parsed_line[5], parsed_line[6], parsed_line[7]))
                        return

        print("The CVE, {}, is not in the signature list\n".format(cve))
        return

    signature = " ".join(user_input)
    signature = format_sig(signature)
    if signature[0] == False:
        print("The input \"{}\" is not a proper signature".format(signature[1]))
        print("Signatures must be in the format \\xnn where n is a-f or 0-9\n")
        return False
       
    #Check if file is empty to avoid index out of bounds error
    if os.stat("database/signatures.txt").st_size != 1:
        with open("database/signatures.txt", "r") as signatures:
            for line in signatures:
                parsed_line = line.strip()
                parsed_line = parsed_line.split(" | ")
                if signature == parsed_line[7]:
                    print("The signature is in the signature list")
                    print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}   Response: {}\nSignature: {}\n".format(parsed_line[0],
                        parsed_line[1], parsed_line[2], parsed_line[3], parsed_line[4], parsed_line[5], parsed_line[6], parsed_line[7]))
                    return

    print("The signature is not in the signature list\n".format(signature))


def sig_add(user_input):
    if len(user_input) == 0:
        print("A signature and name are required\n")
        return False

    signature = ""
    for string in user_input:
        if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
            break
        signature = signature + " " + string
        user_input = user_input[1:]
    
    signature = format_sig(signature)
    if signature[0] == False:
        print("The input \"{}\" is not a proper signature".format(signature[1]))
        print("Signatures must be in the format \\xnn where n is a-f or 0-9\n")
        return False

    if check_sig(signature) == True:
        print("The signature is already in the signature list\n".format(signature))
        return False

    name = platform = service = rank = disclosed = cve = response = ""
    while len(user_input) != 0:
        if user_input[0].casefold() == "-n":
            if name != "":
                print("You can only have one name\n")
                return False

            user_input = user_input[1:]
            for string in user_input:
                if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
                    break
                name = name + " " + string
                user_input = user_input[1:]

            name = format_name(name)
            if name[0] == False:
                print("The input \"{}\" is not a proper name".format(name[1]))
                print("Names cannot begin with a space or contain a \"|\"\n")
                return False

            if check_name(name) == True:
                print("The name, {}, is already in the signature list\n".format(name))
                return False

        elif user_input[0].casefold() == "-p":
            if platform != "":
                print("You can only have one platform\n")
                return False

            user_input = user_input[1:]
            for string in user_input:
                if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
                    break
                platform = platform + " " + string
                user_input = user_input[1:]
            
            platform = format_platform(platform)
            if platform[0] == False:
                print("The input \"{}\" is not a proper platform".format(platform[1]))
                print("Platforms cannot begin with a space or contain a \"|\"\n")
                return False

        elif user_input[0].casefold() == "-s":
            if service != "":
                print("You can only have one service\n")
                return False

            user_input = user_input[1:]
            for string in user_input:
                if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
                    break
                service = service + " " + string
                user_input = user_input[1:]

            service = format_service(service)
            if service[0] == False:
                print("The input \"{}\" is not a proper service".format(service[1]))
                print("Services cannot begin with a space or contain a \"|\"\n")
                return False

        elif user_input[0].casefold() == "-ra":
            if rank != "":
                print("You can only have one rank\n")
                return False

            user_input = user_input[1:]
            for string in user_input:
                if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
                    break
                rank = rank + " " + string
                user_input = user_input[1:]

            rank = format_rank(rank)
            if rank[0] == False:
                print("The input \"{}\" is not a proper rank".format(rank[1]))
                print("Ranks cannot begin with a space or contain a \"|\"\n")
                return False

        elif user_input[0].casefold() == "-d":
            if disclosed != "":
                print("You can only have one disclose date\n")
                return False

            user_input = user_input[1:]
            for string in user_input:
                if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
                    break
                disclosed = disclosed + " " + string
                user_input = user_input[1:]

            disclosed = format_disclosed(disclosed)
            if disclosed[0] == False:
                print("The input \"{}\" is not a proper disclosure date".format(disclosed[1]))
                print("Disclosure dates must be in the form yyyy-mm-dd or yyyy-mm\n")
                return False

        elif user_input[0].casefold() == "-c":
            if cve != "":
                print("You can only have one CVE\n")
                return False

            user_input = user_input[1:]
            for string in user_input:
                if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
                    break
                cve = cve + " " + string
                user_input = user_input[1:]

            cve = format_cve(cve)
            if cve[0] == False:
                print("The input \"{}\" is not a proper CVE".format(cve[1]))
                print("CVEs must be in the format cve-yyyy-nnnn with at least 4 digits in the sequence number portion of the id\n")
                return False

            if check_cve(cve) == True:
                print("The CVE, {}, is already in the signature list\n".format(cve))
                return False

        elif user_input[0].casefold() == "-re":
            if response != "":
                print("You can only have one response\n")
                return False

            user_input = user_input[1:]
            for string in user_input:
                if (string == "-n") or (string == "-p") or (string == "-s") or (string == "-ra") or (string == "-d") or (string == "-c") or (string == "-re"):
                    break
                response = response + " " + string
                user_input = user_input[1:]

            response = format_response(response)
            if response[0] == False:
                print("The input \"{}\" is not a proper resonse".format(response[1]))
                print("Responses must be \"none\" or in the format \"block h:m:s\", where h is the number of hours, m is the number of minutes, and s is the number of seconds")
                return False

    if name == "":
        print("The signature must have a name associated with it\n")
        return False
    if platform == "":
        platform = " "
    if service == "":
        service = " "
    if rank == "":
        rank = " "
    if disclosed == "":
        disclosed = " "
    if cve == "":
        cve = " "
    if response == "":
        response = "none"

    with open("database/signatures.txt", "a") as signatures:
        signatures.write(name + " | " + platform + " | " + service + " | " + rank + " | " + disclosed + " | " + cve + " | " + response + " | " + signature + "\n")


def sig_remove(user_input):
    if len(user_input) == 0:
        print("A signature, name, or cve is required\n")
        return False 

    if user_input[0].casefold() == "-n":
        user_input = user_input[1:]
        name = " ".join(user_input)
        name = format_name(name)
        if name[0] == False:
            print("The input \"{}\" is not a proper name".format(name[1]))
            print("Names cannot begin with a space or contain a \"|\"\n")
            return False

        if check_name(name) == True:
            #check if file is empty to avoid index out of bounds error
            if os.stat("database/signatures.txt").st_size != 1:
                with open("database/signatures.txt", "r+") as signatures:
                    lines = signatures.readlines()
                    signatures.seek(0)
                    signatures.truncate()

                    for line in lines:
                        parsed_line = line.strip()
                        parsed_line = parsed_line.split(" | ")
                        if parsed_line[0] != name:
                            signatures.write(line)
                    return

        print("The name, {}, is not in the signature list\n".format(name))
        return

    if user_input[0].casefold() == "-c":
        user_input = user_input[1:]
        cve = " ".join(user_input)
        cve = format_cve(cve)
        if cve[0] == False:
            print("The input \"{}\" is not a proper CVE".format(cve[1]))
            print("CVEs must be in the format cve-yyyy-nnnn with at least 4 digits in the sequence number portion of the id\n")
            return False

        if check_cve(cve) == True:
            #check if file is empty to avoid index out of bounds error
            if os.stat("database/signatures.txt").st_size != 1:
                with open("database/signatures.txt", "r+") as signatures:
                    lines = signatures.readlines()
                    signatures.seek(0)
                    signatures.truncate()

                    for line in lines:
                        parsed_line = line.strip()
                        parsed_line = parsed_line.split(" | ")
                        if parsed_line[5] != cve:
                            signatures.write(line)
                    return

        print("The CVE, {}, is not in the signature list\n".format(cve))
        return

    signature = " ".join(user_input)
    signature = format_sig(signature)
    if signature[0] == False:
        print("The input \"{}\" is not a proper signature".format(signature[1]))
        print("Signatures must be in the format \\xnn where n is a-f or 0-9\n")
        return False

    if check_sig(signature) == True:
        #check if file is empty to avoid index out of bounds error
        if os.stat("database/signatures.txt").st_size != 1:
            with open("database/signatures.txt", "r+") as signatures:
                lines = signatures.readlines()
                signatures.seek(0)
                signatures.truncate()

                for line in lines:
                    parsed_line = line.strip()
                    parsed_line = parsed_line.split(" | ")
                    if parsed_line[7] != signature:
                        signatures.write(line)
                return

    print("The signature is not in the signature list\n".format(signature))


def sig_print():
    print("\n")
    print("Signatures")
    print("----------")
    #check if file is empty to avoid index out of bounds error
    if os.stat("database/signatures.txt").st_size != 1:
        with open("database/signatures.txt", "r") as siglist:
            for line in siglist:
                parsed_line = line.strip()
                parsed_line = parsed_line.split(" | ")
                print("Name: {}   Platform: {}   Service: {}   Rank: {}   Disclosed: {}   CVE: {}   Response: {}\nSignature: {}".format(parsed_line[0], parsed_line[1],
                    parsed_line[2], parsed_line[3], parsed_line[4], parsed_line[5], parsed_line[6], parsed_line[7]))
                print("---------------------------------\n")


def check_sig(signature):
    #Check if file is empty to avoid index out of bounds error
    if os.stat("database/signatures.txt").st_size != 1:
        with open("database/signatures.txt", "r") as signatures:
            for line in signatures:
                parsed_line = line.strip()
                parsed_line = parsed_line.split(" | ")
                if signature == parsed_line[7]:
                    return True    
    return False


def check_name(name):
    #Check if file is empty to avoid index out of bounds error
    if os.stat("database/signatures.txt").st_size != 1:
        with open("database/signatures.txt", "r") as signatures:
            for line in signatures:
                parsed_line = line.strip()
                parsed_line = parsed_line.split(" | ")
                if name == parsed_line[0]:
                    return True
    return False


def check_cve(cve):
    #check if file is empty to avoid index out of bounds error
    if os.stat("database/signatures.txt").st_size != 1:
        with open("database/signatures.txt", "r") as signatures:
            for line in signatures:
                parsed_line = line.strip()
                parsed_line = parsed_line.split(" | ")
                if cve == parsed_line[5]:
                    return True
    return False


def format_sig(signature):
    signature = signature.strip()
    signature = signature.casefold()
    re_sig = re.compile("^(\\\\x([0-9]|[a-f])([0-9]|[a-f]))+$")
    if re_sig.match(signature) == None:
        return False, signature

    return signature


def format_disclosed(disclosed):
    disclosed = disclosed.strip()
    re_disclosed = re.compile("^([0-9][0-9][0-9][0-9]-(([0][1-9])|([1][0-2]))-(([0][1-9])|([1-2][0-9])|([3][0-1])))|([0-9][0-9][0-9][0-9]-(([0][1-9])|([1][0-2])))$")
    if re_disclosed.match(disclosed) == None:
        return False, disclosed

    return disclosed


def format_cve(cve):
    cve = cve.strip()
    cve = cve.casefold()
    re_cve = re.compile("^cve-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]+$")
    if re_cve.match(cve) == None:
        return False, cve

    return cve


def format_name(name):
    name = name.strip()
    re_name = re.compile("^[^|]+$")
    if re_name.match(name) == None:
        return False, name

    return name


def format_platform(platform):
    platform = platform.strip()
    re_platform = re.compile("^[^|]+$")
    if re_platform.match(platform) == None:
        return False, platform

    return platform


def format_service(service):
    service = service.strip()
    re_service = re.compile("^[^|]+$")
    if re_service.match(service) == None:
        return False, service

    return service


def format_rank(rank):
    rank = rank.strip()
    re_rank = re.compile("^[^|]+$")
    if re_rank.match(rank) == None:
        return False, rank

    return rank


def format_response(response):
    response = response.strip()
    response = response.casefold()
    re_response = re.compile("^(none)|(block (([1-9][0-9][0-9])|([1-9][0-9])|([0-9])):(([1-9][0-9][0-9])|([1-9][0-9])|([0-9])):(([1-9][0-9][0-9])|([1-9][0-9])|([0-9])))$")
    if re_response.match(response) == None:
        return False, response

    return response
