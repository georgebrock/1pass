import os
from unittest import TestCase

from click.testing import CliRunner
from mock import patch

from onepassword.cli import cli


class CLITest(TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_cli_reading_web_form_password_with_multiple_password_attempts(self):
        password_attempts = (i for i in ("incorrect", "badger"))
        with patch('getpass.getpass', lambda prompt: password_attempts.next()):
            args = ['--path', self.keychain_path, 'onetosix']
            result = self.runner.invoke(cli, args)

        assert result.exit_code == 0
        assert result.output == "123456\n"

    def test_cli_with_bad_item_name(self):
        args = ('onetos', '--path', self.keychain_path)
        with patch('getpass.getpass', lambda prompt: 'badger'):
            result = self.runner.invoke(cli, args)
        assert result.exit_code == os.EX_DATAERR
        assert result.output == "1pass: Could not find an item named 'onetos'\n"

    def test_cli_with_fuzzy_matching(self):
        with patch('getpass.getpass', lambda prompt: 'badger'):
            args = ['--fuzzy', '--path', self.keychain_path, 'onetos']
            result = self.runner.invoke(cli, args)
        assert result.exit_code == 0
        assert result.output == "123456\n"

    def test_cli_cancelled_password_prompt(self):
        def keyboard_interrupt(prompt):
            raise KeyboardInterrupt()

        args = ('--path', self.keychain_path, 'onetosix')
        with patch('getpass.getpass', lambda prompt: keyboard_interrupt):
            result = self.runner.invoke(cli, args)
        assert result.exit_code == -1

    def test_correct_password_from_stdin(self):
        args = ('--no-prompt', '--path', self.keychain_path, 'onetosix')
        with patch('getpass.getpass', lambda prompt: self.password_used):
            result = self.runner.invoke(cli, args, input='badger\n')
        assert result.exit_code == 0
        assert result.output == "123456\n"

    def test_incorrect_password_from_stdin(self):
        args = ('--no-prompt', '--path', self.keychain_path, 'onetosix')
        with patch('getpass.getpass', lambda prompt: self.password_used):
            result = self.runner.invoke(cli, args, input='wrong-password\n')
        assert result.exit_code == os.EX_DATAERR
        assert result.output == "1pass: Incorrect master password\n"

    @property
    def keychain_path(self):
        return os.path.join(os.path.dirname(__file__), "data", "1Password.agilekeychain")

    def password_used(self, prompt):
        self.fail("Password prompt was invoked")
