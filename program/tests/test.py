import re
import ahocorasick
import pickle

def test():
    user_input = "test test test".split()
    print(user_input)

    sig = ""
    for string in user_input:
        if string == "-n":
            break
        sig = sig + " " + string
        user_input = user_input[1:]
    print(sig)
    print(user_input)
    print(len(user_input))

def test2():
    line = "name |   |   |   |   | sig".split(" | ")
    print(line)

def test3():
    with open("test.txt", "r") as f:
        lines = f.readlines()
        print(lines)

def test4():
    test = "awda: 14|234 awdawd".split()
    new2 = " ".join(test)
    new = ""
    for string in test:
        new = new + " " + string

    print(new2)
    re_test = re.compile("^[^|]+$")
    if re_test.match(new2) == None:
        print("Worked")

def test5():
    user_input = "input  \n"
    user_input = user_input.split()
    print(user_input)
    user_input = user_input[1:]
    print(len(user_input))
    test = " ".join(user_input)
    print(len(test))

    if user_input == "":
        print("yes")

def test6():
    A = ahocorasick.Automaton()
    for index, key in enumerate('he her hers she'.split()):
        A.add_word(key, index)

    print(A.get('he'))

    A.make_automaton()

    print(A.get('he'))

    string = 'hehibrugshregrhgrkerherhaufeaheshe'
    for index, value in A.iter(string):
        print(index,value)


if __name__ == "__main__":
    test6()


