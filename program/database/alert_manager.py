
def alert_manager(user_input):
    if user_input.casefold() is "printalerts":
        alert_print()
        return True

    if user_input.casefold() is "clearalerts":
        alert_clear()
        return True

def alert_print():
    print("\n")
    print("Alerts")
    print("------")
    with open("alerts.txt", "r") as alerts:
        for line in alerts:
            print(line.strip("\n"))
    print("\n")


def alert_clear():
    with open("alerts.txt", "w+") as alerts:
        alerts.truncate()


def alerts_add(signature, packet):

