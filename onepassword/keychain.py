import json
import os

from onepassword.encryption_key import EncryptionKey


class Keychain(object):
    def __init__(self, path):
        self._path = os.path.expanduser(path)
        self._load_encryption_keys()
        self._load_item_list()
        self._locked = True

    def unlock(self, password):
        unlocker = lambda key: key.unlock(password)
        unlock_results = map(unlocker, self._encryption_keys.values())
        result = reduce(lambda x, y: x and y, unlock_results)
        self._locked = not result
        return result

    def item(self, name):
        if name in self._items:
            item = self._items[name]
            item.decrypt_with(self)
            return item
        else:
            return None

    def key(self, identifier=None, security_level=None):
        """
        Tries to find an encryption key, first using the ``identifier`` and
        if that fails or isn't provided using the ``security_level``.
        Returns ``None`` if nothing matches.
        """
        if identifier:
            try:
                return self._encryption_keys[identifier]
            except KeyError:
                pass
        if security_level:
            for key in self._encryption_keys.values():
                if key.level == security_level:
                    return key

    @property
    def locked(self):
        return self._locked

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
            item = KeychainItem.build(item_definition, self._path)
            self._items[item.name] = item


class KeychainItem(object):
    @classmethod
    def build(cls, row, path):
        identifier = row[0]
        type = row[1]
        name = row[2]
        if type == "webforms.WebForm":
            return WebFormKeychainItem(identifier, name, path, type)
        elif type == "passwords.Password" or type == "wallet.onlineservices.GenericAccount":
            return PasswordKeychainItem(identifier, name, path, type)
        else:
            return KeychainItem(identifier, name, path, type)

    def __init__(self, identifier, name, path, type):
        self.identifier = identifier
        self.name = name
        self.password = None
        self._path = path
        self._type = type

    @property
    def key_identifier(self):
        return self._lazily_load("_key_identifier")

    @property
    def security_level(self):
        return self._lazily_load("_security_level")

    def decrypt_with(self, keychain):
        key = keychain.key(
            identifier=self.key_identifier,
            security_level=self.security_level,
        )
        encrypted_json = self._lazily_load("_encrypted_json")
        decrypted_json = key.decrypt(self._encrypted_json)
        self._data = json.loads(decrypted_json)
        self.password = self._find_password()

    def _find_password(self):
        raise Exception("Cannot extract a password from this type of"
                        " keychain item (%s)" % self._type)

    def _lazily_load(self, attr):
        if not hasattr(self, attr):
            self._read_data_file()
        return getattr(self, attr)

    def _read_data_file(self):
        filename = "%s.1password" % self.identifier
        path = os.path.join(self._path, "data", "default", filename)
        with open(path, "r") as f:
            item_data = json.load(f)

        self._key_identifier = item_data.get("keyID")
        self._security_level = item_data.get("securityLevel")
        self._encrypted_json = item_data["encrypted"]


class WebFormKeychainItem(KeychainItem):
    def _find_password(self):
        for field in self._data["fields"]:
            if field.get("designation") == "password" or \
               field.get("name") == "Password":
                return field["value"]


class PasswordKeychainItem(KeychainItem):
    def _find_password(self):
        return self._data["password"]
