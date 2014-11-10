import getpass
import os
import sys

import click

from .keychain import Keychain

DEFAULT_KEYCHAIN_PATH = "~/Dropbox/1Password.agilekeychain"


@click.command()
@click.argument('item')
@click.option('--path', envvar='ONEPASSWORD_KEYCHAIN', default=DEFAULT_KEYCHAIN_PATH, help="Path to your 1Password.agilekeychain file")
@click.option('--fuzzy', is_flag=True, help="Perform fuzzy matching on the item")
@click.option('--no-prompt', is_flag=True, help="Don't prompt for a password, read from STDIN instead")
def cli(item, path, fuzzy, no_prompt):
    keychain = Keychain(path)

    if no_prompt:
        password = sys.stdin.read().strip()
        keychain.unlock(password)
        if keychain.locked:
            sys.stderr.write("1pass: Incorrect master password\n")
            sys.exit(os.EX_DATAERR)
    else:
        while keychain.locked:
            try:
                keychain.unlock(getpass("Master password: "))
            except KeyboardInterrupt:
                sys.stdout.write("\n")
                sys.exit(0)

    item = keychain.item(item, 70 if fuzzy else 100)

    if item is not None:
        sys.stdout.write("%s\n" % item.password)
    else:
        sys.stderr.write("1pass: Could not find an item named '%s'\n" % (item))
        sys.exit(os.EX_DATAERR)
