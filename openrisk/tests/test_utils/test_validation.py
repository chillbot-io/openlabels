"""
Tests for openlabels.utils.validation module.

Tests input validation for subprocess calls and extended attributes.
"""

import pytest


class TestShellMetacharacters:
    """Tests for SHELL_METACHARACTERS constant."""

    def test_is_frozenset(self):
        """SHELL_METACHARACTERS should be immutable."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert isinstance(SHELL_METACHARACTERS, frozenset)

    def test_contains_backtick(self):
        """Should contain command substitution backtick."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '`' in SHELL_METACHARACTERS

    def test_contains_dollar(self):
        """Should contain variable expansion dollar."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '$' in SHELL_METACHARACTERS

    def test_contains_pipe(self):
        """Should contain pipe operator."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '|' in SHELL_METACHARACTERS

    def test_contains_semicolon(self):
        """Should contain command separator semicolon."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert ';' in SHELL_METACHARACTERS

    def test_contains_ampersand(self):
        """Should contain background/AND operator."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '&' in SHELL_METACHARACTERS

    def test_contains_redirect_operators(self):
        """Should contain redirect operators."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '>' in SHELL_METACHARACTERS
        assert '<' in SHELL_METACHARACTERS

    def test_contains_newline(self):
        """Should contain newline."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '\n' in SHELL_METACHARACTERS

    def test_contains_carriage_return(self):
        """Should contain carriage return."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '\r' in SHELL_METACHARACTERS

    def test_contains_null_byte(self):
        """Should contain null byte."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert '\x00' in SHELL_METACHARACTERS

    def test_exactly_ten_characters(self):
        """Should contain exactly 10 dangerous characters."""
        from openlabels.utils.validation import SHELL_METACHARACTERS

        assert len(SHELL_METACHARACTERS) == 10


class TestValidatePathForSubprocess:
    """Tests for validate_path_for_subprocess function."""

    def test_valid_simple_path(self):
        """Should accept simple valid path."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user/file.txt") is True

    def test_valid_path_with_spaces(self):
        """Should accept path with spaces."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user/my file.txt") is True

    def test_valid_path_with_dots(self):
        """Should accept path with dots."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user/../other/file.txt") is True

    def test_valid_windows_path(self):
        """Should accept Windows-style path."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("C:\\Users\\Admin\\file.txt") is True

    def test_empty_path_rejected(self):
        """Should reject empty path."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("") is False

    def test_none_equivalent_path_rejected(self):
        """Should reject None-like values."""
        from openlabels.utils.validation import validate_path_for_subprocess

        # Empty string is falsy
        assert validate_path_for_subprocess("") is False

    def test_backtick_rejected(self):
        """Should reject path with backtick (command substitution)."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user/`whoami`.txt") is False

    def test_dollar_rejected(self):
        """Should reject path with dollar (variable expansion)."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/$USER/file.txt") is False

    def test_pipe_rejected(self):
        """Should reject path with pipe."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user|rm -rf /") is False

    def test_semicolon_rejected(self):
        """Should reject path with semicolon."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user; rm -rf /") is False

    def test_ampersand_rejected(self):
        """Should reject path with ampersand."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user & rm -rf /") is False

    def test_redirect_greater_rejected(self):
        """Should reject path with > redirect."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user > /etc/passwd") is False

    def test_redirect_less_rejected(self):
        """Should reject path with < redirect."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user < /etc/passwd") is False

    def test_newline_rejected(self):
        """Should reject path with newline."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user\n/etc/passwd") is False

    def test_carriage_return_rejected(self):
        """Should reject path with carriage return."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user\r/etc/passwd") is False

    def test_null_byte_rejected(self):
        """Should reject path with null byte."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/user\x00/etc/passwd") is False

    def test_too_long_path_rejected(self):
        """Should reject path exceeding MAX_PATH_LENGTH."""
        from openlabels.utils.validation import validate_path_for_subprocess
        from openlabels.adapters.scanner.constants import MAX_PATH_LENGTH

        long_path = "/" + "a" * MAX_PATH_LENGTH
        assert validate_path_for_subprocess(long_path) is False

    def test_path_at_max_length_accepted(self):
        """Should accept path at exactly MAX_PATH_LENGTH."""
        from openlabels.utils.validation import validate_path_for_subprocess
        from openlabels.adapters.scanner.constants import MAX_PATH_LENGTH

        exact_path = "/" + "a" * (MAX_PATH_LENGTH - 1)
        assert len(exact_path) == MAX_PATH_LENGTH
        assert validate_path_for_subprocess(exact_path) is True

    def test_path_just_under_max_length_accepted(self):
        """Should accept path just under MAX_PATH_LENGTH."""
        from openlabels.utils.validation import validate_path_for_subprocess
        from openlabels.adapters.scanner.constants import MAX_PATH_LENGTH

        path = "/" + "a" * (MAX_PATH_LENGTH - 2)
        assert validate_path_for_subprocess(path) is True


class TestValidatePathInjectionAttempts:
    """Tests for common injection attack patterns."""

    def test_command_substitution_dollar_paren(self):
        """Should reject $(command) substitution."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/$(whoami)/file") is False

    def test_command_substitution_backtick(self):
        """Should reject `command` substitution."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/home/`id`/file") is False

    def test_command_chaining_semicolon(self):
        """Should reject command chaining with semicolon."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("file.txt; cat /etc/passwd") is False

    def test_command_chaining_and(self):
        """Should reject command chaining with &&."""
        from openlabels.utils.validation import validate_path_for_subprocess

        # Contains &
        assert validate_path_for_subprocess("file.txt && rm -rf /") is False

    def test_background_execution(self):
        """Should reject background execution."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("file.txt & rm -rf /") is False

    def test_file_overwrite_redirect(self):
        """Should reject file overwrite attempts."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("file.txt > /etc/passwd") is False

    def test_env_variable_expansion(self):
        """Should reject environment variable expansion."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("$HOME/file.txt") is False

    def test_null_byte_truncation(self):
        """Should reject null byte truncation attack."""
        from openlabels.utils.validation import validate_path_for_subprocess

        assert validate_path_for_subprocess("/safe/path\x00/etc/passwd") is False


class TestValidateXattrValue:
    """Tests for validate_xattr_value function."""

    def test_valid_simple_value(self):
        """Should accept simple valid value."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("label:pii:ssn") is True

    def test_valid_json_value(self):
        """Should accept JSON-like value."""
        from openlabels.utils.validation import validate_xattr_value

        value = '{"type": "SSN", "confidence": 0.95}'
        assert validate_xattr_value(value) is True

    def test_valid_base64_value(self):
        """Should accept base64-encoded value."""
        from openlabels.utils.validation import validate_xattr_value

        value = "eyJ0eXBlIjogIlNTTiIsICJjb25maWRlbmNlIjogMC45NX0="
        assert validate_xattr_value(value) is True

    def test_valid_uuid_value(self):
        """Should accept UUID value."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("550e8400-e29b-41d4-a716-446655440000") is True

    def test_empty_value_rejected(self):
        """Should reject empty value."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("") is False

    def test_backtick_rejected(self):
        """Should reject value with backtick."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("label`whoami`") is False

    def test_dollar_rejected(self):
        """Should reject value with dollar."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("$HOME") is False

    def test_pipe_rejected(self):
        """Should reject value with pipe."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("value|command") is False

    def test_semicolon_rejected(self):
        """Should reject value with semicolon."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("value; rm -rf /") is False

    def test_ampersand_rejected(self):
        """Should reject value with ampersand."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("value & command") is False

    def test_redirect_rejected(self):
        """Should reject value with redirects."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("value > file") is False
        assert validate_xattr_value("value < file") is False

    def test_newline_rejected(self):
        """Should reject value with newline."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("line1\nline2") is False

    def test_carriage_return_rejected(self):
        """Should reject value with carriage return."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("line1\rline2") is False

    def test_null_byte_rejected(self):
        """Should reject value with null byte."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("value\x00extra") is False

    def test_too_long_value_rejected(self):
        """Should reject value exceeding MAX_XATTR_VALUE_SIZE."""
        from openlabels.utils.validation import validate_xattr_value
        from openlabels.adapters.scanner.constants import MAX_XATTR_VALUE_SIZE

        long_value = "a" * (MAX_XATTR_VALUE_SIZE + 1)
        assert validate_xattr_value(long_value) is False

    def test_value_at_max_size_accepted(self):
        """Should accept value at exactly MAX_XATTR_VALUE_SIZE."""
        from openlabels.utils.validation import validate_xattr_value
        from openlabels.adapters.scanner.constants import MAX_XATTR_VALUE_SIZE

        exact_value = "a" * MAX_XATTR_VALUE_SIZE
        assert validate_xattr_value(exact_value) is True

    def test_value_just_under_max_size_accepted(self):
        """Should accept value just under MAX_XATTR_VALUE_SIZE."""
        from openlabels.utils.validation import validate_xattr_value
        from openlabels.adapters.scanner.constants import MAX_XATTR_VALUE_SIZE

        value = "a" * (MAX_XATTR_VALUE_SIZE - 1)
        assert validate_xattr_value(value) is True


class TestValidateXattrValueEdgeCases:
    """Tests for edge cases in xattr value validation."""

    def test_whitespace_only_accepted(self):
        """Whitespace-only value should be accepted (not empty)."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("   ") is True

    def test_unicode_accepted(self):
        """Unicode values should be accepted."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value("标签:敏感") is True

    def test_special_chars_not_in_blocklist_accepted(self):
        """Special chars not in blocklist should be accepted."""
        from openlabels.utils.validation import validate_xattr_value

        # These are special but not dangerous for shell
        assert validate_xattr_value("value@#%^*()[]{}") is True
        assert validate_xattr_value("path/to/file") is True
        assert validate_xattr_value("key=value") is True

    def test_quotes_accepted(self):
        """Quotes should be accepted (handled by shell quoting)."""
        from openlabels.utils.validation import validate_xattr_value

        assert validate_xattr_value('value with "quotes"') is True
        assert validate_xattr_value("value with 'quotes'") is True


class TestMaxConstants:
    """Tests for MAX_* constants values."""

    def test_max_path_length_is_4096(self):
        """MAX_PATH_LENGTH should be 4096."""
        from openlabels.adapters.scanner.constants import MAX_PATH_LENGTH

        assert MAX_PATH_LENGTH == 4096

    def test_max_xattr_value_size_is_65536(self):
        """MAX_XATTR_VALUE_SIZE should be 65536."""
        from openlabels.adapters.scanner.constants import MAX_XATTR_VALUE_SIZE

        assert MAX_XATTR_VALUE_SIZE == 65536

    def test_max_path_length_is_reasonable(self):
        """MAX_PATH_LENGTH should be reasonable for filesystems."""
        from openlabels.adapters.scanner.constants import MAX_PATH_LENGTH

        # Linux PATH_MAX is typically 4096
        # Windows MAX_PATH is 260 but can be extended
        assert 260 <= MAX_PATH_LENGTH <= 32767

    def test_max_xattr_value_size_is_reasonable(self):
        """MAX_XATTR_VALUE_SIZE should be reasonable for xattrs."""
        from openlabels.adapters.scanner.constants import MAX_XATTR_VALUE_SIZE

        # Most filesystems support at least 64KB for xattr values
        assert MAX_XATTR_VALUE_SIZE >= 1024
        assert MAX_XATTR_VALUE_SIZE <= 1024 * 1024  # 1MB max reasonable
