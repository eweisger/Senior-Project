import unittest
from database.sig_manager import *

class test_sigs(unittest.TestCase):

    def test_response_regex(self):
        self.assertTrue(format_response("block 0:0:0\n")[0])
        self.assertTrue(format_response("block 999:999:999\n")[0])
        self.assertTrue(format_response("none\n")[0])
        
        self.assertFalse(format_response("\n")[0])
        self.assertFalse(format_response("block \n")[0])
        self.assertFalse(format_response("block 0:0:1000\n")[0])
        self.assertFalse(format_response("block 0:1000:0\n")[0])
        self.assertFalse(format_response("block 1000:0:0\n")[0])

    def test_rank_regex(self):
        self.assertTrue(format_rank("testme\n")[0])
        self.assertTrue(format_rank("test: me\n"[0]))
        self.assertTrue(format_rank(" test me \n")[0])
        
        self.assertFalse(format_rank("\n")[0])
        self.assertFalse(format_rank("test|me")[0])
        self.assertFalse(format_rank(" | testme")[0])

    def test_service_regex(self):
        self.assertTrue(format_service("testme\n")[0])
        self.assertTrue(format_service("test: me\n"[0]))
        self.assertTrue(format_service(" test me \n")[0])
 
        self.assertFalse(format_service("\n")[0])
        self.assertFalse(format_service("test|me")[0])
        self.assertFalse(format_service(" | testme")[0])

    def test_platform_regex(self):
        self.assertTrue(format_platform("testme\n")[0])
        self.assertTrue(format_platform("test: me\n"[0]))
        self.assertTrue(format_platform(" test me \n")[0])
        
        self.assertFalse(format_platform("\n")[0])       
        self.assertFalse(format_platform("test|me")[0])
        self.assertFalse(format_platform(" | testme")[0])

    def test_name_regex(self):
        self.assertTrue(format_name("testme\n")[0])
        self.assertTrue(format_name("test: me\n"[0]))
        self.assertTrue(format_name(" test me \n")[0])
        
        self.assertFalse(format_name("\n")[0])
        self.assertFalse(format_name("test|me")[0])
        self.assertFalse(format_name(" | testme")[0])

    def test_cve_regex(self):
        self.assertTrue(format_cve("cve-0000-0000\n")[0])
        self.assertTrue(format_cve("cve-9999-9999\n")[0])
        self.assertTrue(format_cve("cve-1029-000099990000\n")[0])

        self.assertFalse(format_cve("\n")[0])
        self.assertFalse(format_cve("cve\n")[0])
        self.assertFalse(format_cve("cve-000-0121\n")[0])
        self.assertFalse(format_cve("cve-0000-012\n")[0])

    def test_disclosed_regex(self):
        self.assertTrue(format_disclosed("0000-01\n")[0])
        self.assertTrue(format_disclosed("9999-12\n")[0])
        self.assertTrue(format_disclosed("0000-01-01\n")[0])
        self.assertTrue(format_disclosed("9999-12-31\n")[0])

        self.assertFalse(format_disclosed("\n")[0])
        self.assertFalse(format_disclosed("00000-01\n")[0])
        self.assertFalse(format_disclosed("0000-00\n")[0])
        self.assertFalse(format_disclosed("0000-13\n")[0])
        self.assertFalse(format_disclosed("0000-111\n")[0])
        self.assertFalse(format_disclosed("0000-01-00\n")[0])
        self.assertFalse(format_disclosed("0000-01-32\n")[0])
        #self.assertFalse(format_disclosed("0000-01-011\n")[1])

    def test_sig_regex(self):
        self.assertTrue(format_sig("\\x00\n")[0])
        self.assertTrue(format_sig("\\x11\n")[0])
        self.assertTrue(format_sig("\\x99\n")[0])
        self.assertTrue(format_sig("\\xaa\n")[0])
        self.assertTrue(format_sig("\\xff\n")[0])
        self.assertTrue(format_sig("\\x00\\x11\\x99\\xaa\\xff\n")[0])

        self.assertFalse(format_sig("\n")[0])
        self.assertFalse(format_sig("\\x\n")[0])
        self.assertFalse(format_sig("\\x012\n")[0])
        self.assertFalse(format_sig("\\xgg\n")[0])

    def test_sig_add(self):
        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()

        self.assertEqual(sig_add("\\x01 -n n1 -p p1 -s s1 -ra ra1 -d 0000-01 -c cve-0000-0001 -re none\n".split()), None)
        self.assertEqual(sig_add("\\x02 -n n2\n".split()), None)
        self.assertEqual(sig_add("\\x03 -n n3 -re block 0:0:0\n".split()), None)
        self.assertEqual(sig_add("\\x04 -n n4 -re block 999:999:999\n".split()), None)

        self.assertFalse(sig_add(""))
        self.assertFalse(sig_add("\\x101\n".split()))
        self.assertFalse(sig_add("\\x01 -n n01\n".split()))
        self.assertFalse(sig_add("\\x05 -n n01 -n \n".split()))
        self.assertFalse(sig_add("\\x05 -n n0|1\n".split()))
        self.assertFalse(sig_add("\\x05 -n n1\n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -p p1 -p \n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -p p|1\n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -s s1 -s \n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -s s|1\n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -ra ra -ra \n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -ra r|a\n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -d 0000-01 -d \n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -d 024\n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -c cve-0000-00005 -c \n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -c cve-0000-0001\n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -c cve-0123910-9985483\n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -re none -re \n".split()))
        self.assertFalse(sig_add("\\x05 -n n5 -re no\n".split()))
        self.assertFalse(sig_add("\\x05\n".split()))

        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()

    def test_sig_check(self):
        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()

        sig_add("\\x01 -n n1 -c cve-0000-0001\n".split())
        sig_add("\\x02 -n n2 -c cve-0000-0002\n".split())

        self.assertEqual(sig_check("\\x00\n".split()), None)
        self.assertEqual(sig_check("-n n\n".split()), None)
        self.assertEqual(sig_check("-c cve-0000-0000\n".split()), None)
        self.assertEqual(sig_check("\\x01\n".split()), None)  
        self.assertEqual(sig_check("-n n1\n".split()), None)
        self.assertEqual(sig_check("-c cve-0000-0001\n".split()), None)

        self.assertFalse(sig_check(""))
        self.assertFalse(sig_check("-n lo|l\n".split()))
        self.assertFalse(sig_check("-c cve-010101-1010101\n".split()))
        self.assertFalse(sig_check("\\x01010\n".split()))

        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()

    def test_sig_remove(self):
        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()

        sig_add("\\x01 -n n1 -c cve-0000-0001\n".split())
        sig_add("\\x02 -n n2 -c cve-0000-0002\n".split())
        sig_add("\\x03 -n n3 -c cve-0000-0003\n".split())
        sig_add("\\x04 -n n4 -c cve-0000-0004\n".split())

        self.assertEqual(sig_remove("\\x01\n".split()), None)
        self.assertEqual(sig_remove("\\x01\n".split()), None)
        self.assertEqual(sig_remove("-n n2".split()), None)
        self.assertEqual(sig_remove("-n n2\n".split()), None)
        self.assertEqual(sig_remove("-c cve-0000-0003\n".split()), None)
        self.assertEqual(sig_remove("-c cve-0000-0003\n".split()), None)

        self.assertFalse(sig_remove(""))
        self.assertFalse(sig_remove("-n n|alow\n".split()))
        self.assertFalse(sig_remove("-c cve-12310-12038014\n".split()))
        self.assertFalse(sig_remove("\\x010101\n".split()))

        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()

    def test_sig_other(self):
        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()

        sig_print()

        sig_add("\\x01 -n n1 -c cve-0000-0001\n".split())
        sig_add("\\x02 -n n2 -c cve-0000-0002\n".split())

        sig_print()

        self.assertTrue(check_sig("\\x01"))
        self.assertFalse(check_sig("\\x03"))
        self.assertTrue(check_name("n1"))
        self.assertFalse(check_name("n3"))
        self.assertTrue(check_cve("cve-0000-0001"))
        self.assertFalse(check_cve("cve-0000-0003"))

        with open("database/signatures.txt", "r+") as sigs:
            sigs.truncate()


