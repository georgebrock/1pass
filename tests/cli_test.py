import os
from unittest import TestCase
# Python 2+3 compatibilty
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

from onepassword.cli import CLI


class CLITest(TestCase):
    def setUp(self):
        self.output = StringIO()
        self.error = StringIO()
        self.input = StringIO()

    def test_cli_reading_web_form_password_with_multiple_password_attempts(self):
        password_attempts = (i for i in ("incorrect", "badger"))
        cli = self.build_cli(
            getpass=lambda prompt: next(password_attempts),
            arguments=("--path", self.keychain_path, "onetosix",),
        )

        cli.run()

        self.assert_output("123456\n")
        self.assert_no_error_output()

    def test_cli_with_bad_item_name(self):
        cli = self.build_cli(
            getpass=lambda prompt: "badger",
            arguments=("--path", self.keychain_path, "onetos",),
        )

        self.assert_exit_status(os.EX_DATAERR, cli.run)
        self.assert_no_output()
        self.assert_error_output("1pass: Could not find an item named 'onetos'\n")

    def test_cli_with_fuzzy_matching(self):
        cli = self.build_cli(
            getpass=lambda prompt: "badger",
            arguments=("--fuzzy", "--path", self.keychain_path, "onetos",),
        )
        cli.run()

        self.assert_output("123456\n")
        self.assert_no_error_output()

    def test_cli_cancelled_password_prompt(self):
        def keyboard_interrupt(prompt):
            raise KeyboardInterrupt()
        cli = self.build_cli(
            getpass=keyboard_interrupt,
            arguments=("--path", self.keychain_path, "onetosix",),
        )

        self.assert_exit_status(0, cli.run)
        self.assert_output("\n")
        self.assert_no_error_output()

    def test_correct_password_from_stdin(self):
        def flunker(prompt):
            self.fail("Password prompt was invoked")
        self.input.write("badger\n")
        self.input.seek(0)
        cli = self.build_cli(
            getpass=flunker,
            arguments=("--no-prompt", "--path", self.keychain_path, "onetosix",),
        )
        cli.run()

        self.assert_output("123456\n")
        self.assert_no_error_output()

    def test_incorrect_password_from_stdin(self):
        def flunker(prompt):
            self.fail("Password prompt was invoked")
        self.input.write("wrong-password\n")
        self.input.seek(0)
        cli = self.build_cli(
            getpass=flunker,
            arguments=("--no-prompt", "--path", self.keychain_path, "onetosix",),
        )

        self.assert_exit_status(os.EX_DATAERR, cli.run)
        self.assert_no_output()
        self.assert_error_output("1pass: Incorrect master password\n")

    def build_cli(self, **kwargs):
        cli_kwargs = {
            "stdin": self.input,
            "stdout": self.output,
            "stderr": self.error,
        }
        cli_kwargs.update(kwargs)
        return CLI(**cli_kwargs)

    def assert_exit_status(self, expected_status, func):
        try:
            func()
        except SystemExit as exit:
            self.assertEqual(expected_status, exit.code)
        else:
            self.fail("Expected a SystemExit to be raised")

    def assert_output(self, expected_output):
        self.assertEqual(expected_output, self.output.getvalue())

    def assert_no_output(self):
        self.assert_output("")

    def assert_error_output(self, expected_output):
        self.assertEqual(expected_output, self.error.getvalue())

    def assert_no_error_output(self):
        self.assert_error_output("")

    @property
    def keychain_path(self):
        return os.path.join(os.path.dirname(__file__), "data", "1Password.agilekeychain")
