from base64 import b64decode
from Crypto.Cipher import AES
from pbkdf2 import pbkdf2_bin


class EncryptionKey(object):
    SALTED_PREFIX = "Salted__"
    DEFAULT_SALT = "\x00" * 16
    MINIMUM_ITERATIONS = 1000

    def __init__(self, data, iterations=0):
        self._set_salt_and_data(data)
        self._set_iterations(iterations)

    def _set_salt_and_data(self, data):
        decoded_data = b64decode(data)
        if decoded_data.startswith(self.SALTED_PREFIX):
            self.salt = decoded_data[8:16]
            self.data = decoded_data[16:]
        else:
            self.salt = self.DEFAULT_SALT
            self.data = decoded_data

    def _set_iterations(self, iterations):
        self.iterations = max(int(iterations), self.MINIMUM_ITERATIONS)

    def _derive(self, password):
        derived_key_and_iv = pbkdf2_bin(password, self.salt, self.iterations,
                                        keylen=32)
        self.derived_key = derived_key_and_iv[0:16]
        self.derived_initialisation_vector = derived_key_and_iv[16:]

    def _decrypt(self, password):
        self._derive(password)
        aes = AES.new(self.derived_key, AES.MODE_CBC, self.derived_initialisation_vector)
        self.decrypted_key = aes.decrypt(self.data)
