from base64 import b64encode, b64decode
from unittest import TestCase

from onepassword.encryption_key import EncryptionKey


class EncryptionKeyTest(TestCase):
    def test_unsalted_data(self):
        key = EncryptionKey(data=b64encode("Unsalted data"))
        self.assertEquals("\x00" * 16, key.salt)
        self.assertEquals("Unsalted data", key.data)

    def test_salted_data(self):
        key = EncryptionKey(data=b64encode("Salted__SSSSSSSSDDDDDDDD"))
        self.assertEquals("SSSSSSSS", key.salt)
        self.assertEquals("DDDDDDDD", key.data)

    def test_iterations_with_string(self):
        key = EncryptionKey(data="", iterations="40000")
        self.assertEquals(40000, key.iterations)

    def test_iterations_with_number(self):
        key = EncryptionKey(data="", iterations=5000)
        self.assertEquals(5000, key.iterations)

    def test_iterations_default(self):
        key = EncryptionKey(data="")
        self.assertEquals(1000, key.iterations)

    def test_iterations_minimum(self):
        key = EncryptionKey(data="", iterations=500)
        self.assertEquals(1000, key.iterations)
