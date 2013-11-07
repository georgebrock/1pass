import os
from unittest import TestCase
from StringIO import StringIO

from onepassword.cli import CLI


class CLITest(TestCase):
    def setUp(self):
        self.output = StringIO()
        self.error = StringIO()

    def test_cli_reading_web_form_password_with_multiple_password_attempts(self):
        password_attempts = (i for i in ("incorrect", "badger"))
        cli = CLI(
            getpass=lambda prompt: password_attempts.next(),
            stdout=self.output,
            stderr=self.error,
            arguments=("--path", self.keychain_path, "onetosix",),
        )
        cli.run()

        self.assert_output("123456\n")
        self.assert_no_error_output()

    def test_cli_with_bad_item_name(self):
        cli = CLI(
            getpass=lambda prompt: "badger",
            stdout=self.output,
            stderr=self.error,
            arguments=("--path", self.keychain_path, "onetos",),
        )

        self.assert_exit_status(os.EX_DATAERR, cli.run)
        self.assert_no_output()
        self.assert_error_output("1pass: Could not find an item named 'onetos'\n")

    def test_cli_with_fuzzy_matching(self):
        cli = CLI(
            getpass=lambda prompt: "badger",
            stdout=self.output,
            stderr=self.error,
            arguments=("--fuzzy", "--path", self.keychain_path, "onetos",),
        )
        cli.run()

        self.assert_output("123456\n")
        self.assert_no_error_output()

    def test_cli_cancelled_password_prompt(self):
        def keyboard_interrupt(prompt):
            raise KeyboardInterrupt()
        cli = CLI(
            getpass=keyboard_interrupt,
            stdout=self.output,
            stderr=self.error,
            arguments=("--path", self.keychain_path, "onetosix",),
        )

        self.assert_exit_status(0, cli.run)
        self.assert_output("\n")
        self.assert_no_error_output()

    def assert_exit_status(self, expected_status, func):
        try:
            func()
        except SystemExit as exit:
            self.assertEquals(expected_status, exit.code)
        else:
            self.fail("Expected a SystemExit to be raised")

    def assert_output(self, expected_output):
        self.assertEquals(expected_output, self.output.getvalue())

    def assert_no_output(self):
        self.assert_output("")

    def assert_error_output(self, expected_output):
        self.assertEquals(expected_output, self.error.getvalue())

    def assert_no_error_output(self):
        self.assert_error_output("")

    @property
    def keychain_path(self):
        return os.path.join(os.path.dirname(__file__), "data", "1Password.agilekeychain")
