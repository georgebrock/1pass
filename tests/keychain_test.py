from mock import Mock
import os
from unittest import TestCase

from onepassword.keychain import Keychain, KeychainItem


class KeychainTest(TestCase):
    def test_locked_flag(self):
        keychain = Keychain(self.data_path)
        self.assertTrue(keychain.locked)
        self.assertTrue(keychain.unlock("badger"))
        self.assertFalse(keychain.locked)

    @property
    def data_path(self):
        return os.path.join(os.path.dirname(__file__), "data", "1Password.agilekeychain")


class KeychainItemTest(TestCase):
    def test_initialisation_with_contents_data(self):
        item = KeychainItem(self.example_row, path=self.data_path)
        self.assertEquals("onetosix", item.name)
        self.assertEquals("CEA5EA6531FC4BE9B7D7F89B5BB18B66", item.identifier)

    def test_key_identifier(self):
        item = KeychainItem(self.example_row, path=self.data_path)
        self.assertEquals("525E210E0B4C49799D7E47DD8E789C78", item.key_identifier)

    def test_decrypt(self):
        mock_key = Mock()
        mock_key.decrypt.return_value = """{"fields":[
            {"name":"Username","value":"user","designation":"username"},
            {"value":"abcdef","name":"Password","designation":"password"}
        ]}"""
        item = KeychainItem(self.example_row, path=self.data_path)

        self.assertIsNone(item.password)
        item.decrypt_with(mock_key)
        self.assertEquals("abcdef", item.password)

    @property
    def data_path(self):
        return os.path.join(os.path.dirname(__file__), "data", "1Password.agilekeychain")

    @property
    def example_row(self):
        return [
            "CEA5EA6531FC4BE9B7D7F89B5BB18B66",
            "webforms.WebForm",
            "onetosix",
            "example.com",
            1361021221,
            "",
            0,
            "N",
        ]
