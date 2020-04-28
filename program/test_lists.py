import unittest
from database.list_manager import *

class test_lists(unittest.TestCase):

    def test_ip_regex(self):
        self.assertTrue(check_ip_format("255.255.255.255\n")[0])
        self.assertTrue(check_ip_format("0.0.0.0\n")[0])
        
        self.assertFalse(check_ip_format("\n")[0])
        self.assertFalse(check_ip_format("0\n")[0])
        self.assertFalse(check_ip_format("0.\n")[0])
        self.assertFalse(check_ip_format("0.0\n")[0])
        self.assertFalse(check_ip_format("0.0.\n")[0])
        self.assertFalse(check_ip_format("0.0.0\n")[0])
        self.assertFalse(check_ip_format("0.0.0.\n")[0])

    def test_response_regex(self):
        self.assertTrue(format_response("block 0:0:0\n")[0])
        self.assertTrue(format_response("block 999:999:999\n")[0])
        self.assertTrue(format_response("none\n")[0])

        self.assertFalse(format_response("\n")[0])
        self.assertFalse(format_response("block \n")[0])
        self.assertFalse(format_response("block 0:0:1000\n")[0])
        self.assertFalse(format_response("block 0:1000:0\n")[0])
        self.assertFalse(format_response("block 1000:0:0\n")[0])

    def test_whitelist_commands(self):
        with open("database/whitelist.txt", "r+") as whitelist:
            whitelist.truncate()
        with open("database/blacklist.txt", "r+") as blacklist:
            blacklist.truncate()

        self.assertEqual(whitelist_print(), None)
        self.assertFalse(whitelist_check("0.0.0.0"))
        self.assertEqual(whitelist_add("0.0.0.0\n"), None)
        blacklist_add("1.1.1.1\n".split())
        self.assertFalse(whitelist_add(""))
        self.assertFalse(whitelist_add("1.1\n"))
        self.assertFalse(whitelist_add("0.0.0.0\n"))
        self.assertFalse(whitelist_add("1.1.1.1\n"))
        self.assertTrue(whitelist_check("0.0.0.0"))
        self.assertEqual(whitelist_print(), None)

        with open("database/whitelist.txt", "r+") as whitelist:
            whitelist.truncate()
        with open("database/blacklist.txt", "r+") as blacklist:
            blacklist.truncate()

    def test_blacklist_commands(self):
        with open("database/whitelist.txt", "r+") as whitelist:
            whitelist.truncate()
        with open("database/blacklist.txt", "r+") as blacklist:
            blacklist.truncate()

        self.assertEqual(blacklist_print(), None)
        self.assertFalse(blacklist_check("0.0.0.0\n"))
        self.assertEqual(blacklist_add("0.0.0.0\n".split()), None)
        self.assertEqual(blacklist_add("255.255.255.255 -re none\n".split()), None)
        self.assertEqual(blacklist_add("2.2.2.2 -re block 0:0:0\n".split()), None)
        whitelist_add("1.1.1.1\n")
        self.assertFalse(blacklist_add("".split()))
        self.assertFalse(blacklist_add("1.1\n".split()))
        self.assertFalse(blacklist_add("0.0.0.0\n".split()))
        self.assertFalse(blacklist_add("1.1.1.1\n".split()))
        self.assertFalse(blacklist_add("3.3.3.3 -re \n".split()))
        self.assertFalse(blacklist_add("3.3.3.3 -re none -re none\n".split()))
        self.assertFalse(blacklist_add("3.3.3.3 -re block 1000:1000:1000\n".split()))
        self.assertTrue(blacklist_check("0.0.0.0"))
        self.assertEqual(blacklist_print(), None)

        with open("database/whitelist.txt", "r+") as whitelist:
            whitelist.truncate()
        with open("database/blacklist.txt", "r+") as blacklist:
            blacklist.truncate()

    def test_general_commands(self):
        with open("database/whitelist.txt", "r+") as whitelist:
            whitelist.truncate()
        with open("database/blacklist.txt", "r+") as blacklist:
            blacklist.truncate()
       
        self.assertFalse(check_ip(""))
        self.assertFalse(check_ip("0.1\n"))
        self.assertEqual(check_ip("1.1.1.1\n"), None)
        blacklist_add("1.1.1.1\n".split())
        whitelist_add("0.0.0.0\n")
        whitelist_add("2.2.2.2\n")
        blacklist_add("3.3.3.3\n".split())
        self.assertEqual(check_ip("1.1.1.1\n"), None)
        self.assertEqual(check_ip("0.0.0.0\n"), None)

        self.assertFalse(remove_ip(""))
        self.assertFalse(remove_ip("1.0\n"))
        self.assertEqual(remove_ip("2.2.2.2\n"), None)
        self.assertEqual(remove_ip("1.1.1.1\n"), None)
        self.assertEqual(remove_ip("0.0.0.0\n"), None)
        self.assertEqual(remove_ip("255.255.255.255\n"), None)

        with open("database/whitelist.txt", "r+") as whitelist:
            whitelist.truncate()
        with open("database/blacklist.txt", "r+") as blacklist:
            blacklist.truncate()


