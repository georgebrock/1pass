import json
import os

from onepassword.encryption_key import EncryptionKey


class Keychain(object):
    def __init__(self, path):
        self._path = path
        self._load_encryption_keys()
        self._load_item_list()

    def unlock(self, password):
        unlocker = lambda key: key.unlock(password)
        unlock_results = map(unlocker, self._encryption_keys.values())
        return reduce(lambda x, y: x and y, unlock_results)

    def item(self, name):
        if name in self._items:
            item = self._items[name]
            key = self._encryption_keys[item.key_identifier]
            item.decrypt_with(key)
            return item
        else:
            return None

    def _load_encryption_keys(self):
        path = os.path.join(self._path, "data", "default", "encryptionKeys.js")
        with open(path, "r") as f:
            key_data = json.load(f)

        self._encryption_keys = {}
        for key_definition in key_data["list"]:
            key = EncryptionKey(**key_definition)
            self._encryption_keys[key.identifier] = key

    def _load_item_list(self):
        path = os.path.join(self._path, "data", "default", "contents.js")
        with open(path, "r") as f:
            item_list = json.load(f)

        self._items = {}
        for item_definition in item_list:
            item = KeychainItem(item_definition, self._path)
            self._items[item.name] = item


class KeychainItem(object):
    def __init__(self, row, path):
        self.identifier = row[0]
        self.name = row[2]
        self.password = None
        self._path = path

    @property
    def key_identifier(self):
        return self._lazily_load("_key_identifier")

    def decrypt_with(self, key):
        encrypted_json = self._lazily_load("_encrypted_json")
        decrypted_json = key.decrypt(self._encrypted_json)[:-1]
        data = json.loads(decrypted_json)
        for field in data["fields"]:
            if field["designation"] == "password" or field["name"] == "Password":
                self.password = field["value"]

    def _lazily_load(self, attr):
        if not hasattr(self, attr):
            self._read_data_file()
        return getattr(self, attr)

    def _read_data_file(self):
        filename = "%s.1password" % self.identifier
        path = os.path.join(self._path, "data", "default", filename)
        with open(path, "r") as f:
            item_data = json.load(f)

        self._key_identifier = item_data["keyID"]
        self._encrypted_json = item_data["encrypted"]
