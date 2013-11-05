import os
from unittest import TestCase

from onepassword import Keychain


class IntegrationTest(TestCase):
    def test_unlock_and_read_web_form_password(self):
        keychain = Keychain(path=self.keychain_path)

        unlock_result = keychain.unlock("wrong-password")
        self.assertFalse(unlock_result)

        unlock_result = keychain.unlock("badger")
        self.assertTrue(unlock_result)

        self.assertIsNone(keychain.item("does-not-exist"))
        self.assertEquals("123456", keychain.item("onetosix").password)
        self.assertEquals("abcdef", keychain.item("atof").password)

    def test_unlock_and_read_generated_password(self):
        keychain = Keychain(path=self.keychain_path)

        keychain.unlock("badger")
        self.assertEquals("foobar", keychain.item("foobar").password)

    def test_unlock_and_read_generic_account_password(self):
        keychain = Keychain(path=self.keychain_path)

        keychain.unlock("badger")
        self.assertEquals("flibble", keychain.item("Generic Account").password)

    def test_unlock_and_read_with_fuzzy_matching(self):
        keychain = Keychain(path=self.keychain_path)

        keychain.unlock("badger")
        item = keychain.item("foobr", fuzzy_threshold=70)
        self.assertEquals("foobar", item.password)

    @property
    def keychain_path(self):
        return os.path.join(os.path.dirname(__file__), "data", "1Password.agilekeychain")
