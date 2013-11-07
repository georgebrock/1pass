=====
1pass
=====

A command line interface (and Python library) for reading passwords from
`1Password <https://agilebits.com/onepassword>`_.

Command line usage
==================

To get a password::

    1pass mail.google.com

By default this will look in ``~/Dropbox/1Password.agilekeychain``. If that's
not where you keep your keychain::

    1pass --path ~/whatever/1Password.agilekeychain mail.google.com

Or, you can set your keychain path as an enviornment variable::

    export ONEPASSWORD_KEYCHAIN=/path/to/keychain

    1pass mail.google.com

By default, the name you pass on the command line must match the name of an
item in your 1Password keychain exactly. To avoid this, fuzzy matching is
made possible with the ``--fuzzy`` flag::

    1pass --fuzzy mail.goog

If you don't want to be prompted for your password, you can use the
``--no-prompt`` flag and provide the password via standard input instead::

    emit_master_password | 1pass --no-prompt mail.google.com

Python usage
============

The interface is very simple::

    from onepassword import Keychain

    my_keychain = Keychain(path="~/Dropbox/1Password.agilekeychain")
    my_keychain.unlock("my-master-password")
    my_keychain.item("An item's name").password

An example of real-world use
============================

I wrote this so I could add the following line to my ``.muttrc`` file::

    set imap_pass = "`1pass 'Google: personal'`"

Now, whenever I start ``mutt``, I am prompted for my 1Password Master Password
and not my Gmail password.

The ``--no-prompt`` flag is very useful when configuring ``mutt`` and PGP.
``mutt`` passes the PGP passphrase via standard in, so by inserting ``1pass``
into this pipline I can use my 1Password master password when prompted for my
PGP keyphrase::

    set pgp_decrypt_command="1pass --no-prompt pgp-passphrase | gpg --passphrase-fd 0 ..."

Contributors
============

* Pip Taylor <https://github.com/pipt>
* Adam Coddington <https://github.com/latestrevision>
* Ash Berlin <https://github.com/ashb>
* Zach Allaun <https://github.com/zachallaun>

License
=======

*1pass* is licensed under the MIT license. See the license file for details.

While it is designed to read ``.agilekeychain`` bundles created by 1Password,
*1pass* isn't officially sanctioned or supported by
`AgileBits <https://agilebits.com/>`_. I do hope they like it though.
