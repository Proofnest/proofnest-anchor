"""
ProofNest Anchor CLI Tests
--------------------------
Tests for CLI commands and utilities.
"""

import pytest
import json
import os
from pathlib import Path
from click.testing import CliRunner

from proofnest_anchor.cli import (
    cli,
    sha256_file,
    load_registry,
    save_registry,
    sanitize_proof_filename,
    AnchorError,
    NotInitializedError,
    FileNotAnchoredError,
    OTSNotInstalledError,
    MAX_MESSAGE_LENGTH,
)


class TestSanitizeProofFilename:
    """Tests for path sanitization (security)."""

    def test_simple_filename(self):
        """Simple filename should pass through."""
        assert sanitize_proof_filename("test.py") == "test.py"

    def test_path_with_directories(self):
        """Path with directories should use underscores."""
        assert sanitize_proof_filename("src/main.py") == "src_main.py"

    def test_path_traversal_attack(self):
        """Path traversal attempts should be sanitized."""
        result = sanitize_proof_filename("../../../etc/passwd")
        assert ".." not in result
        assert "/" not in result
        assert result == "etc_passwd"

    def test_backslash_path(self):
        """Windows-style paths should be handled."""
        result = sanitize_proof_filename("src\\lib\\main.py")
        assert "\\" not in result

    def test_special_characters(self):
        """Special characters should be replaced."""
        result = sanitize_proof_filename("file<>:name.py")
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_long_filename(self):
        """Very long filenames should be truncated."""
        long_name = "a" * 300 + ".py"
        result = sanitize_proof_filename(long_name)
        assert len(result) <= 200

    def test_empty_after_sanitize(self):
        """Empty result should become 'unnamed'."""
        result = sanitize_proof_filename("../../../")
        assert result == "unnamed"


class TestSha256File:
    """Tests for file hashing."""

    def test_hash_file(self, sample_file):
        """Should compute correct SHA256 hash."""
        hash_result = sha256_file(sample_file)
        assert len(hash_result) == 64  # SHA256 hex is 64 chars
        assert all(c in '0123456789abcdef' for c in hash_result)

    def test_same_content_same_hash(self, temp_project_dir):
        """Same content should produce same hash."""
        file1 = temp_project_dir / "file1.txt"
        file2 = temp_project_dir / "file2.txt"
        content = "Same content"
        file1.write_text(content)
        file2.write_text(content)

        assert sha256_file(file1) == sha256_file(file2)

    def test_different_content_different_hash(self, temp_project_dir):
        """Different content should produce different hash."""
        file1 = temp_project_dir / "file1.txt"
        file2 = temp_project_dir / "file2.txt"
        file1.write_text("Content A")
        file2.write_text("Content B")

        assert sha256_file(file1) != sha256_file(file2)


class TestRegistry:
    """Tests for registry load/save."""

    def test_load_empty_registry(self, initialized_anchor_dir):
        """Should load empty registry."""
        registry = load_registry(initialized_anchor_dir)
        assert registry["files"] == {}
        assert registry["version"] == "1.0"

    def test_save_and_load_registry(self, initialized_anchor_dir):
        """Should save and load registry correctly."""
        registry = {
            "files": {
                "test.py": {
                    "hash": "abc123",
                    "anchored_at": "2025-01-01T00:00:00",
                    "status": "pending"
                }
            },
            "version": "1.0"
        }
        save_registry(initialized_anchor_dir, registry)
        loaded = load_registry(initialized_anchor_dir)

        assert loaded["files"]["test.py"]["hash"] == "abc123"

    def test_load_nonexistent_registry(self, temp_project_dir):
        """Should return default for nonexistent registry."""
        anchor_dir = temp_project_dir / ".anchor"
        anchor_dir.mkdir()
        registry = load_registry(anchor_dir)
        assert registry["files"] == {}


class TestExceptions:
    """Tests for custom exceptions."""

    def test_anchor_error_exists(self):
        """AnchorError should be defined."""
        assert issubclass(AnchorError, Exception)

    def test_not_initialized_error(self):
        """NotInitializedError should inherit from AnchorError."""
        assert issubclass(NotInitializedError, AnchorError)

    def test_file_not_anchored_error(self):
        """FileNotAnchoredError should inherit from AnchorError."""
        assert issubclass(FileNotAnchoredError, AnchorError)

    def test_ots_not_installed_error(self):
        """OTSNotInstalledError should inherit from AnchorError."""
        assert issubclass(OTSNotInstalledError, AnchorError)


class TestCLIInit:
    """Tests for 'anchor init' command."""

    def test_init_creates_directory(self, temp_project_dir):
        """init should create .anchor directory."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=temp_project_dir):
            os.chdir(temp_project_dir)
            result = runner.invoke(cli, ['init'])

            assert result.exit_code == 0
            assert (temp_project_dir / ".anchor").exists()
            assert (temp_project_dir / ".anchor" / "proofs").exists()
            assert (temp_project_dir / ".anchor" / "config.yml").exists()
            assert (temp_project_dir / ".anchor" / "registry.json").exists()

    def test_init_already_exists(self, initialized_anchor_dir):
        """init should warn if already initialized."""
        runner = CliRunner()
        project_dir = initialized_anchor_dir.parent

        with runner.isolated_filesystem(temp_dir=project_dir):
            os.chdir(project_dir)
            result = runner.invoke(cli, ['init'])

            assert "already exists" in result.output.lower()


class TestCLIStatus:
    """Tests for 'anchor status' command."""

    def test_status_empty(self, initialized_anchor_dir):
        """status should show no files when empty."""
        runner = CliRunner()
        project_dir = initialized_anchor_dir.parent

        with runner.isolated_filesystem(temp_dir=project_dir):
            os.chdir(project_dir)
            result = runner.invoke(cli, ['status'])

            assert "no files anchored" in result.output.lower() or result.exit_code == 0


class TestCLIVersion:
    """Tests for version option."""

    def test_version_option(self):
        """--version should show version."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--version'])

        assert result.exit_code == 0
        assert "proofnest-anchor" in result.output.lower()


class TestConstants:
    """Tests for security constants."""

    def test_max_message_length(self):
        """MAX_MESSAGE_LENGTH should be defined."""
        assert MAX_MESSAGE_LENGTH == 1024

    def test_max_files_constant(self):
        """MAX_FILES_TO_ANCHOR should be defined."""
        from proofnest_anchor.cli import MAX_FILES_TO_ANCHOR
        assert MAX_FILES_TO_ANCHOR == 10000
