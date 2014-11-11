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
            click.echo("1pass: Incorrect master password", err=True)
            sys.exit(os.EX_DATAERR)
    else:
        while keychain.locked:
            keychain.unlock(getpass.getpass("Master password: "))

    found_item = keychain.item(item, 70 if fuzzy else 100)

    if found_item is not None:
        click.echo(found_item.password)
    else:
        click.echo("1pass: Could not find an item named '%s'" % (item), err=True)
        sys.exit(os.EX_DATAERR)
