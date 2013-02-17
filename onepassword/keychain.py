import json
import os

from onepassword.encryption_key import EncryptionKey


class Keychain(object):
    def __init__(self, path):
        self._path = path
        self._load_encryption_keys()

    def unlock(self, password):
        unlocker = lambda key: key.unlock(password)
        unlock_results = map(unlocker, self._encryption_keys.values())
        return reduce(lambda x, y: x and y, unlock_results)

    def item(self, name):
        pass

    def _load_encryption_keys(self):
        path = os.path.join(self._path, "data", "default", "encryptionKeys.js")
        with open(path, "r") as f:
            key_data = json.load(f)

        self._encryption_keys = {}
        for key_definition in key_data["list"]:
            level = key_definition["level"]
            self._encryption_keys[level] = EncryptionKey(**key_definition)
