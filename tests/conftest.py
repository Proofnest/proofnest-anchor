"""
ProofNest Anchor Test Fixtures
"""

import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def initialized_anchor_dir(temp_project_dir):
    """Create an initialized .anchor directory."""
    anchor_dir = temp_project_dir / ".anchor"
    anchor_dir.mkdir()
    (anchor_dir / "proofs").mkdir()

    # Create config.yml
    config_content = """auto_anchor:
  - "*.py"
  - "*.md"
  - "!__pycache__/**"
author: "Test User"
"""
    (anchor_dir / "config.yml").write_text(config_content)

    # Create empty registry
    (anchor_dir / "registry.json").write_text('{"files": {}, "version": "1.0"}')

    yield anchor_dir


@pytest.fixture
def sample_file(temp_project_dir):
    """Create a sample file to anchor."""
    file_path = temp_project_dir / "test_file.py"
    file_path.write_text("# Test file content\nprint('hello')\n")
    return file_path
