import argparse
import getpass
import os
import sys

from onepassword import Keychain

DEFAULT_KEYCHAIN_PATH = "~/Dropbox/1Password.agilekeychain"

class CLI(object):
    """
    The 1pass command line interface.
    """

    def __init__(self, stdout=sys.stdout, stderr=sys.stderr,
                 getpass=getpass.getpass, arguments=sys.argv[1:]):
        self.stdout = stdout
        self.stderr = stderr
        self.getpass = getpass
        self.arguments = self.argument_parser().parse_args(arguments)

    def run(self):
        """
        The main entry point, performs the appropriate action for the given
        arguments.
        """
        keychain = Keychain(self.arguments.path)
        while keychain.locked:
            try:
                keychain.unlock(self.getpass("Master password: "))
            except KeyboardInterrupt:
                self.stdout.write("\n")
                sys.exit(0)

        if self.arguments.fuzzy:
            item = keychain.item(self.arguments.item, fuzzy_threshold=70)
        else:
            item = keychain.item(self.arguments.item)

        if item is not None:
            self.stdout.write("%s\n" % item.password)
        else:
            self.stderr.write("1pass: Could not find an item named '%s'\n" % (
                self.arguments.item,
            ))
            sys.exit(os.EX_DATAERR)

    def argument_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("item", help="The name of the password to decrypt")
        parser.add_argument(
            "--path",
            default=os.environ.get('ONEPASSWORD_KEYCHAIN', DEFAULT_KEYCHAIN_PATH),
            help="Path to your 1Password.agilekeychain file",
        )
        parser.add_argument(
            "--fuzzy",
            action="store_true",
            help="Perform fuzzy matching on the item",
        )
        return parser
