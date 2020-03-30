import collections
from test_two import test_two

def test():
    test = "1 || 2 || 3 || 4 || "
    test = test.split(" || ")
    print(test)
    if test[4] is "":
        print("yes")


if __name__ == "__main__":
    test()


