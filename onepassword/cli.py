import argparse
import getpass
import os
import sys

from onepassword import Keychain

DEFAULT_KEYCHAIN_PATH = "~/Dropbox/1Password/1Password.agilekeychain"

class CLI(object):
    """
    The 1pass command line interface.
    """

    def __init__(self, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
                 getpass=getpass.getpass, arguments=sys.argv[1:]):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.getpass = getpass
        self.arguments = self.argument_parser().parse_args(arguments)
        self.keychain = Keychain(self.arguments.path)

    def run(self):
        """
        The main entry point, performs the appropriate action for the given
        arguments.
        """
        if not self.arguments.item:
            for k in self.keychain.get_items(): self.stdout.write("%s\n" % k)
            return

        self._unlock_keychain()

        item = self.keychain.item(
            self.arguments.item,
            fuzzy_threshold=self._fuzzy_threshold(),
        )

        if item is not None:
            if self.arguments.all:
                for d in item._data:
                    self.stdout.write("%s\n"%d)
                    if d == 'fields':
                        for i in item._data[d]:
                            self.stdout.write("\t%s: %s\n"%(i['name'], i['value']))
                    elif d == 'URLs':
                        for i in item._data[d]:
                            self.stdout.write("\t%s\n"%(i['url']))
                    else:
                        self.stdout.write("\t%s\n" % item._data[d])
            elif self.arguments.username:
                self.stdout.write("%s %s\n" % (item.username, item.password))
            else:
                self.stdout.write("%s\n" % item.password)
        else:
            self.stderr.write("1pass: Could not find an item named '%s'\n" % (
                self.arguments.item,
            ))
            sys.exit(os.EX_DATAERR)

    def argument_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("item", help="The name of the key to decrypt,"
            " if ommited prints out the list of all keys in the keychain", nargs="?")
        parser.add_argument(
            "-p",
            "--path",
            default=os.environ.get('ONEPASSWORD_KEYCHAIN', DEFAULT_KEYCHAIN_PATH),
            help="Path to your 1Password.agilekeychain file",
        )
        parser.add_argument(
            "-f",
            "--fuzzy",
            action="store_true",
            help="Perform fuzzy matching on the item",
        )
        parser.add_argument(
            "-n",
            "--no-prompt",
            action="store_true",
            help="Don't prompt for a password, read from STDIN instead",
        )
        parser.add_argument(
            "-a",
            "--all",
            action="store_true",
            help="Print all information stored for the item.",
        )
        parser.add_argument(
            "-u",
            "--username",
            action="store_true",
            help="Print username and password stored for the item.",
        )
        return parser

    def _unlock_keychain(self):
        if self.arguments.no_prompt:
            self._unlock_keychain_stdin()
        else:
            self._unlock_keychain_prompt()

    def _unlock_keychain_stdin(self):
        password = self.stdin.read().strip()
        self.keychain.unlock(password)
        if self.keychain.locked:
            self.stderr.write("1pass: Incorrect master password\n")
            sys.exit(os.EX_DATAERR)

    def _unlock_keychain_prompt(self):
        while self.keychain.locked:
            try:
                self.keychain.unlock(self.getpass("Master password: "))
            except KeyboardInterrupt:
                self.stdout.write("\n")
                sys.exit(0)

    def _fuzzy_threshold(self):
        if self.arguments.fuzzy:
            return 70
        else:
            return 100
