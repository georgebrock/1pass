import os
from unittest import TestCase

from onepassword import Keychain


class IntegrationTest(TestCase):
    def test_unlock_and_read_password(self):
        path = os.path.join(os.path.dirname(__file__), "data")
        keychain = Keychain(data_directory=path)

        unlock_result = keychain.unlock("wrong-password")
        self.assertFalse(unlock_result)

        unlock_result = keychain.unlock("badger")
        self.assertTrue(unlock_result)

        self.assertEquals("123456", keychain.get_password("onetosix"))
        self.assertEquals("abcdef", keychain.get_password("atof"))
        self.assertNone(keychain.get_password("does-not-exist"))
