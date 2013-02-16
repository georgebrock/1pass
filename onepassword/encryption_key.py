from base64 import b64decode
from Crypto.Cipher import AES
from pbkdf2 import pbkdf2_bin


class SaltyString(object):
    SALTED_PREFIX = "Salted__"
    ZERO_INIT_VECTOR = "\x00" * 16

    def __init__(self, base64_encoded_string):
        decoded_data = b64decode(base64_encoded_string)
        if decoded_data.startswith(self.SALTED_PREFIX):
            self.salt = decoded_data[8:16]
            self.data = decoded_data[16:]
        else:
            self.salt = self.ZERO_INIT_VECTOR
            self.data = decoded_data


class EncryptionKey(object):
    MINIMUM_ITERATIONS = 1000

    def __init__(self, data, iterations=0, validation=""):
        self.data = SaltyString(data)
        self._set_iterations(iterations)
        self._validation = SaltyString(validation)

    def decrypt(self, password):
        derived_key, derived_init_vector = self._derive(password)
        aes = AES.new(derived_key, AES.MODE_CBC, derived_init_vector)
        return aes.decrypt(self.data.data)

    def _set_iterations(self, iterations):
        self.iterations = max(int(iterations), self.MINIMUM_ITERATIONS)

    def _derive(self, password):
        derived_key_and_iv = pbkdf2_bin(password, self.data.salt, self.iterations,
                                        keylen=32)
        return (
            derived_key_and_iv[0:16],
            derived_key_and_iv[16:],
        )
