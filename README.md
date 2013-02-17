# 1pass

A command line interface (and Python library) for reading passwords from
[1Password][1Password].

## Command line usage

To get a password:

    bin/1pass mail.google.com

By default this will look in `~/Dropbox/1Password.agilekeychain`. If that's not
where you keep your keychain:

    bin/1pass --path ~/whatever/1Password.agilekeychain mail.google.com

The name you pass on the command line must exactly match the name of an item in
your 1Password keychain.

## Python usage

You'll need to install the requirements:

    pip install -r requirements_dev.txt

After that, the interface is very simple:

    from onepassword import Keychain

    my_keychain = Keychain(path="~/Dropbox/1Password.agilekeychain")
    my_keychain.unlock("my-master-password")
    my_keychain.item("An item's name").password

## An example of real-world use

I wrote this so I could add the following line to my `.muttrc` file:

    set imap_pass = "`~/code/1pass/bin/1pass 'Gooogle: personal'`"

Now, whenever I start `mutt`, I am prompted for my 1Password Master Password and
not my Gmail password.

## License

`1pass` is licensed under the MIT license. See the license file for details.

While it is designed to read `.agilekeychain` bundles created by 1Password,
`1pass` isn't officially sanctioned or supported by [AgileBits][AgileBits]. I do
hope they like it though.

[1Password]: https://agilebits.com/onepassword
[AgileBits]: https://agilebits.com/
