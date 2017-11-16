import argparse
import getpass
import os
import pyperclip
import sys
import webbrowser

from onepassword import Keychain

DEFAULT_KEYCHAIN_PATH = "~/Dropbox/1Password.agilekeychain"

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
        self._unlock_keychain()

        item = self.keychain.item(
            self.arguments.item,
            fuzzy_threshold=self._fuzzy_threshold(),
        )

        if item is not None:
            self.produce(item)
        else:
            self.stderr.write("1pass: Could not find an item named '%s'\n" % (
                self.arguments.item,
            ))
            sys.exit(os.EX_DATAERR)

    def produce(self, item):
        # Show info if needed
        if self.arguments.info:
            self.stdout.write("Item info:\n")
            self.stdout.write("  identifier: %s\n" % item.identifier)
            self.stdout.write("  name      : %s\n" % item.name)
            self.stdout.write("  username  : %s\n" % item.username)
            self.stdout.write("  website   : %s\n" % item.website)

        # Determine if we're using username or password
        if self.arguments.user:
            key = "username"
            val = item.username
        else:
            key = "password"
            val = item.password

        # Print or copy the item
        if self.arguments.copy:
            self.stdout.write("%s copied to clipboard\n" % key)
            pyperclip.copy(val)
        else:
            self.stdout.write("%s\n" % val)

        # Open the website
        if self.arguments.open:
            url = item.website
            if url is None:
                self.stderr.write("Can't find the website url")
                sys.exit(os.EX_DATAERR)
            self.stdout.write("Opening %s in a browser\n" % url)
            webbrowser.open(url, new=2, autoraise=True)

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
        parser.add_argument(
            "--no-prompt",
            action="store_true",
            help="Don't prompt for a password, read from STDIN instead",
        )
        parser.add_argument(
            "-c", "--copy",
            action="store_true",
            help="Copy the password to the clipboard, instead of printing it",
        )
        parser.add_argument(
            "-u", "--user",
            action="store_true",
            help="Instead of password, use the username",
        )
        parser.add_argument(
            "-i", "--info",
            action="store_true",
            help="Print the info about the found item",
        )
        parser.add_argument(
            "-o", "--open",
            action="store_true",
            help="Open a given page in the browser",
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
