"""
PROOFNEST Anchor CLI - git commit for your IP

Usage:
    anchor init          Initialize .anchor/ directory
    anchor commit <file> Timestamp a file to Bitcoin
    anchor status        Show pending/confirmed anchors
    anchor verify <file> Verify a file hasn't changed
    anchor history       Show all anchored files

© 2025 Stellanium Ltd.
"""

import click
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from proofnest_anchor import __version__

try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    rprint = print

# Constants
ANCHOR_DIR = ".anchor"
CONFIG_FILE = "config.yml"
REGISTRY_FILE = "registry.json"
PROOFS_DIR = "proofs"
MAX_MESSAGE_LENGTH = 1024  # Security: limit message size
MAX_FILES_TO_ANCHOR = 10000  # Security: prevent DoS from huge directories
MAX_FILE_SIZE = 100 * 1024 * 1024  # Security: 100MB limit to prevent DoS
MAX_REGISTRY_SIZE = 10 * 1024 * 1024  # Security: 10MB limit for registry.json
MAX_CONFIG_SIZE = 1024 * 1024  # Security: 1MB limit for config.yml


def sanitize_proof_filename(rel_path: str) -> str:
    """
    Sanitize a relative path to create a safe proof filename.

    Security: Prevents path traversal attacks.

    Args:
        rel_path: Relative path like "src/main.py" or "../../../etc/passwd"

    Returns:
        Safe filename like "src_main.py" or "etc_passwd"
    """
    import re
    # Remove any ".." components (path traversal)
    parts = rel_path.replace("\\", "/").split("/")
    safe_parts = [p for p in parts if p and p != ".." and p != "."]
    # Join with underscore and remove any remaining dangerous characters
    safe_name = "_".join(safe_parts)
    # Only allow alphanumeric, underscore, hyphen, dot
    safe_name = re.sub(r'[^a-zA-Z0-9_\-.]', '_', safe_name)
    # Limit length
    if len(safe_name) > 200:
        safe_name = safe_name[:200]
    return safe_name or "unnamed"

console = Console() if RICH_AVAILABLE else None


def _is_path_within(child: Path, parent: Path) -> bool:
    """
    Check if child path is within parent path.

    Python 3.8 compatible alternative to Path.is_relative_to() (added in 3.9).
    """
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


class AnchorError(Exception):
    """Base exception for PROOFNEST Anchor errors."""
    pass


class NotInitializedError(AnchorError):
    """Raised when .anchor directory doesn't exist."""
    pass


class FileNotAnchoredError(AnchorError):
    """Raised when file is not in registry."""
    pass


class OTSNotInstalledError(AnchorError):
    """Raised when OpenTimestamps client is not installed."""
    pass


def error_exit(message: str, code: int = 1):
    """Print error message and exit."""
    if RICH_AVAILABLE:
        rprint(f"[red]Error: {message}[/red]")
    else:
        rprint(f"Error: {message}")
    sys.exit(code)


def warn(message: str):
    """Print warning message."""
    if RICH_AVAILABLE:
        rprint(f"[yellow]Warning: {message}[/yellow]")
    else:
        rprint(f"Warning: {message}")


def success(message: str):
    """Print success message."""
    if RICH_AVAILABLE:
        rprint(f"[green]{message}[/green]")
    else:
        rprint(message)


def check_ots_installed() -> bool:
    """Check if OpenTimestamps client is installed."""
    try:
        result = subprocess.run(
            ["ots", "--version"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def load_config(anchor_dir: Path) -> dict:
    """Load the config.yml file."""
    config_path = anchor_dir / CONFIG_FILE
    if not config_path.exists():
        return {}

    if not YAML_AVAILABLE:
        warn("YAML not available. Run: pip install pyyaml")
        return {}

    try:
        # Security: Check file size before parsing to prevent YAML bomb DoS
        file_size = config_path.stat().st_size
        if file_size > MAX_CONFIG_SIZE:
            warn(f"Config file too large ({file_size:,} bytes), skipping")
            return {}

        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        warn(f"Invalid config.yml: {e}")
        return {}


def get_files_to_anchor(anchor_dir: Path) -> List[Path]:
    """Get list of files matching auto_anchor patterns from config."""
    config = load_config(anchor_dir)
    patterns = config.get("auto_anchor", [])

    if not patterns:
        return []

    # Find the project root (parent of .anchor)
    project_root = anchor_dir.parent.resolve()

    matched_files = set()
    exclude_patterns = []
    files_scanned = 0

    for pattern in patterns:
        if pattern.startswith("!"):
            # Negation pattern
            exclude_patterns.append(pattern[1:])
        else:
            # Include pattern - walk through files
            for path in project_root.rglob("*"):
                files_scanned += 1
                # Security: Limit total files to prevent DoS
                if files_scanned > MAX_FILES_TO_ANCHOR:
                    warn(f"Too many files (>{MAX_FILES_TO_ANCHOR}). Consider narrowing auto_anchor patterns.")
                    break
                if path.is_file():
                    # Security: Safe relative_to with try-except
                    try:
                        # Resolve symlinks and check path is within project
                        resolved = path.resolve()
                        if not _is_path_within(resolved, project_root):
                            continue  # Skip files outside project (symlink escape)
                        rel_path = resolved.relative_to(project_root)
                    except (ValueError, OSError):
                        continue  # Skip paths that can't be resolved
                    if fnmatch.fnmatch(str(rel_path), pattern) or fnmatch.fnmatch(path.name, pattern):
                        matched_files.add(path)
            if files_scanned > MAX_FILES_TO_ANCHOR:
                break

    # Remove excluded files
    for exclude in exclude_patterns:
        to_remove = set()
        for path in matched_files:
            try:
                rel_path = path.resolve().relative_to(project_root)
            except (ValueError, OSError):
                to_remove.add(path)  # Remove paths that can't be resolved
                continue
            if fnmatch.fnmatch(str(rel_path), exclude) or fnmatch.fnmatch(path.name, exclude):
                to_remove.add(path)
        matched_files -= to_remove

    return sorted(matched_files)


def get_anchor_dir() -> Path:
    """Find .anchor directory in current or parent directories."""
    current = Path.cwd()
    while current != current.parent:
        anchor_path = current / ANCHOR_DIR
        if anchor_path.exists():
            return anchor_path
        current = current.parent
    return Path.cwd() / ANCHOR_DIR


def sha256_file(filepath: Path) -> str:
    """Calculate SHA256 hash of a file."""
    try:
        # Security: Check file size before reading to prevent DoS
        file_size = filepath.stat().st_size
        if file_size > MAX_FILE_SIZE:
            error_exit(
                f"File too large: {filepath} ({file_size:,} bytes). "
                f"Max allowed: {MAX_FILE_SIZE:,} bytes (100MB)"
            )

        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except PermissionError:
        error_exit(f"Permission denied: {filepath}")
    except IOError as e:
        error_exit(f"Cannot read file {filepath}: {e}")


def load_registry(anchor_dir: Path) -> dict:
    """Load the registry file."""
    registry_path = anchor_dir / REGISTRY_FILE
    if registry_path.exists():
        try:
            # Security: Check file size before parsing to prevent JSON DoS
            file_size = registry_path.stat().st_size
            if file_size > MAX_REGISTRY_SIZE:
                warn(f"Registry file too large ({file_size:,} bytes), creating new one")
                return {"files": {}, "version": "1.0"}

            with open(registry_path) as f:
                return json.load(f)
        except json.JSONDecodeError:
            warn(f"Registry file corrupted, creating new one")
            return {"files": {}, "version": "1.0"}
        except PermissionError:
            error_exit(f"Permission denied: {registry_path}")
    return {"files": {}, "version": "1.0"}


def save_registry(anchor_dir: Path, registry: dict):
    """Save the registry file."""
    registry_path = anchor_dir / REGISTRY_FILE
    try:
        with open(registry_path, "w") as f:
            json.dump(registry, f, indent=2, default=str)
    except PermissionError:
        error_exit(f"Permission denied: {registry_path}")
    except IOError as e:
        error_exit(f"Cannot write registry: {e}")


def run_ots_command(args: list) -> Tuple[bool, str]:
    """Run an OpenTimestamps command."""
    try:
        result = subprocess.run(
            ["ots"] + args,
            capture_output=True,
            text=True,
            timeout=60  # 60 second timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except FileNotFoundError:
        return False, "OpenTimestamps not installed. Run: pip install opentimestamps-client"
    except subprocess.TimeoutExpired:
        return False, "OpenTimestamps command timed out. Check your internet connection."
    except Exception as e:
        return False, f"OTS error: {e}"


# CLI Commands

@click.group()
@click.version_option(version=__version__, prog_name="proofnest-anchor")
def cli():
    """
    ⚓ PROOFNEST Anchor - git commit for your IP

    Timestamp your files to Bitcoin in seconds.
    Prove prior art. Forever.

    Quick start:

        anchor init

        anchor commit myfile.py

    © 2025 Stellanium Ltd.
    """
    pass


@cli.command()
def init():
    """Initialize .anchor/ directory in current folder."""
    anchor_dir = Path.cwd() / ANCHOR_DIR

    if anchor_dir.exists():
        rprint("[yellow]⚠️  .anchor/ already exists[/yellow]" if RICH_AVAILABLE else "Warning: .anchor/ already exists")
        return

    # Create directory structure
    anchor_dir.mkdir()
    (anchor_dir / PROOFS_DIR).mkdir()

    # Create config file
    config_content = """# PROOFNEST Anchor Configuration
# https://github.com/proofnest/proofnest-anchor

# Files to auto-anchor (glob patterns)
auto_anchor:
  - "*.md"
  - "*.py"
  - "*.js"
  - "*.ts"
  - "!node_modules/**"
  - "!.git/**"
  - "!__pycache__/**"

# Your information (for legal exports)
author: ""
email: ""
organization: ""

# Default license for anchored files
license: ""
"""
    with open(anchor_dir / CONFIG_FILE, "w") as f:
        f.write(config_content)

    # Create empty registry
    save_registry(anchor_dir, {"files": {}, "version": "1.0"})

    # Create .gitignore for proofs
    with open(anchor_dir / ".gitignore", "w") as f:
        f.write("# Keep .ots files out of git (they're in proofs/)\n")

    rprint("[green]✓ Initialized .anchor/ directory[/green]" if RICH_AVAILABLE else "✓ Initialized .anchor/ directory")
    rprint("")
    rprint("Next steps:")
    rprint("  1. Edit .anchor/config.yml with your info")
    rprint("  2. Run: anchor commit <file>")


def get_staged_files() -> List[str]:
    """Get list of files staged in git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
            # Filter only existing files (not deleted)
            return [f for f in files if Path(f).exists()]
        return []
    except FileNotFoundError:
        return []


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--all", "-a", "anchor_all", is_flag=True, help="Anchor all files matching config patterns")
@click.option("--staged", "-s", is_flag=True, help="Anchor all files staged in git")
@click.option("--message", "-m", help="Add a note to this anchor")
def commit(files, anchor_all, staged, message):
    """Timestamp file(s) to Bitcoin."""
    anchor_dir = get_anchor_dir()

    if not anchor_dir.exists():
        error_exit("Not an anchor repository. Run 'anchor init' first.")

    if not files and not anchor_all and not staged:
        error_exit("Usage: anchor commit <file> or anchor commit --all or anchor commit --staged")

    # Check OTS is installed
    if not check_ots_installed():
        error_exit("OpenTimestamps not installed. Run: pip install opentimestamps-client")

    # Security: Validate message length
    if message and len(message) > MAX_MESSAGE_LENGTH:
        error_exit(f"Message too long: {len(message)} chars (max {MAX_MESSAGE_LENGTH})")

    registry = load_registry(anchor_dir)
    proofs_dir = anchor_dir / PROOFS_DIR

    # Get files to anchor
    if staged:
        staged_files = get_staged_files()
        if not staged_files:
            rprint("[yellow]No staged files to anchor.[/yellow]" if RICH_AVAILABLE else "No staged files to anchor.")
            return
        files_to_anchor = staged_files
        rprint(f"Found {len(files_to_anchor)} staged files...")
    elif anchor_all:
        auto_files = get_files_to_anchor(anchor_dir)
        if not auto_files:
            warn("No files match auto_anchor patterns in config.yml")
            return
        files_to_anchor = [str(f) for f in auto_files]
        rprint(f"Found {len(files_to_anchor)} files matching patterns...")
    else:
        files_to_anchor = list(files)

    for filepath in files_to_anchor:
        path = Path(filepath)
        if not path.exists():
            rprint(f"[red]✗ File not found: {filepath}[/red]" if RICH_AVAILABLE else f"✗ File not found: {filepath}")
            continue

        # Calculate hash
        file_hash = sha256_file(path)

        # Check if already anchored with same hash
        # Security: Safe relative_to with fallback
        try:
            if path.is_absolute():
                rel_path = str(path.resolve().relative_to(Path.cwd().resolve()))
            else:
                rel_path = str(path)
        except (ValueError, OSError):
            rel_path = str(path)  # Fallback to original path
        if rel_path in registry["files"]:
            existing = registry["files"][rel_path]
            if existing.get("hash") == file_hash:
                rprint(f"[yellow]⏭️  Already anchored (unchanged): {rel_path}[/yellow]" if RICH_AVAILABLE else f"⏭️  Already anchored: {rel_path}")
                continue

        rprint(f"[blue]⚓ Anchoring: {rel_path}[/blue]" if RICH_AVAILABLE else f"⚓ Anchoring: {rel_path}")
        rprint(f"   Hash: {file_hash[:16]}..." if RICH_AVAILABLE else f"   Hash: {file_hash[:16]}...")

        # Run OTS stamp
        success, output = run_ots_command(["stamp", str(path)])

        if success:
            # Move .ots file to proofs directory
            ots_file = Path(str(path) + ".ots")
            if ots_file.exists():
                # Security: sanitize filename to prevent path traversal
                safe_filename = sanitize_proof_filename(rel_path)
                dest = proofs_dir / (safe_filename + ".ots")
                # Double-check dest is within proofs_dir
                if not _is_path_within(dest, proofs_dir):
                    rprint(f"[red]✗ Security: Invalid path for {rel_path}[/red]" if RICH_AVAILABLE else f"✗ Security: Invalid path")
                    continue

                # Security (v0.2.1): Atomic rename with symlink check
                # Reject if source is a symlink (prevents symlink attacks)
                if ots_file.is_symlink():
                    rprint(f"[red]✗ Security: OTS file is a symlink: {ots_file}[/red]" if RICH_AVAILABLE else f"✗ Security: symlink rejected")
                    try:
                        ots_file.unlink()  # Remove the symlink
                    except OSError:
                        pass
                    continue

                try:
                    import shutil
                    shutil.move(str(ots_file), str(dest))
                    # Post-move verification: ensure dest is not a symlink
                    if dest.is_symlink():
                        rprint(f"[red]✗ Security: Destination became symlink[/red]" if RICH_AVAILABLE else f"✗ Security error")
                        try:
                            dest.unlink()
                        except OSError:
                            pass
                        continue
                except (OSError, shutil.Error) as e:
                    rprint(f"[red]✗ Failed to move OTS file: {e}[/red]" if RICH_AVAILABLE else f"✗ Move failed: {e}")
                    continue

                # Update registry
                registry["files"][rel_path] = {
                    "hash": file_hash,
                    "anchored_at": datetime.now().isoformat(),
                    "proof_file": str(dest.relative_to(anchor_dir)),
                    "status": "pending",
                    "message": message,
                    "calendars": ["alice", "bob", "finney", "catallaxy"]
                }

                rprint(f"[green]✓ Submitted to Bitcoin (4 calendars)[/green]" if RICH_AVAILABLE else "✓ Submitted to Bitcoin")
            else:
                rprint(f"[yellow]⚠️  OTS file not created[/yellow]" if RICH_AVAILABLE else "⚠️  OTS file not created")
        else:
            rprint(f"[red]✗ Failed: {output}[/red]" if RICH_AVAILABLE else f"✗ Failed: {output}")

    save_registry(anchor_dir, registry)

    rprint("")
    rprint("[dim]Proof will be ready in ~1-2 hours.[/dim]" if RICH_AVAILABLE else "Proof ready in ~1-2 hours.")
    rprint("[dim]Run 'anchor status' to check.[/dim]" if RICH_AVAILABLE else "Run 'anchor status' to check.")


@cli.command()
def status():
    """Show status of all anchored files."""
    anchor_dir = get_anchor_dir()

    if not anchor_dir.exists():
        rprint("[red]Error: Not an anchor repository. Run 'anchor init' first.[/red]" if RICH_AVAILABLE else "Error: Run 'anchor init' first")
        sys.exit(1)

    registry = load_registry(anchor_dir)

    if not registry["files"]:
        rprint("[yellow]No files anchored yet. Run: anchor commit <file>[/yellow]" if RICH_AVAILABLE else "No files anchored yet.")
        return

    if RICH_AVAILABLE:
        table = Table(title="⚓ Anchored Files")
        table.add_column("File", style="cyan")
        table.add_column("Hash", style="dim")
        table.add_column("Status", style="green")
        table.add_column("Anchored", style="dim")

        for filepath, info in registry["files"].items():
            status_str = "✓ Confirmed" if info.get("status") == "confirmed" else "⏳ Pending"
            table.add_row(
                filepath,
                info["hash"][:12] + "...",
                status_str,
                info["anchored_at"][:10]
            )

        console.print(table)
    else:
        rprint("\nAnchored Files:")
        rprint("-" * 60)
        for filepath, info in registry["files"].items():
            status_str = "✓" if info.get("status") == "confirmed" else "⏳"
            rprint(f"{status_str} {filepath}")
            rprint(f"   Hash: {info['hash'][:16]}...")
            rprint(f"   Date: {info['anchored_at'][:10]}")
        rprint("-" * 60)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
def verify(file):
    """Verify a file hasn't changed since anchoring."""
    anchor_dir = get_anchor_dir()

    if not anchor_dir.exists():
        rprint("[red]Error: Not an anchor repository.[/red]" if RICH_AVAILABLE else "Error: Not an anchor repository.")
        sys.exit(1)

    registry = load_registry(anchor_dir)
    path = Path(file)
    # Security: Safe relative_to with fallback
    try:
        if path.is_absolute():
            rel_path = str(path.resolve().relative_to(Path.cwd().resolve()))
        else:
            rel_path = str(path)
    except (ValueError, OSError):
        rel_path = str(path)

    if rel_path not in registry["files"]:
        rprint(f"[yellow]File not anchored: {rel_path}[/yellow]" if RICH_AVAILABLE else f"File not anchored: {rel_path}")
        rprint("Run: anchor commit " + rel_path)
        sys.exit(1)

    # Calculate current hash
    current_hash = sha256_file(path)
    stored_hash = registry["files"][rel_path]["hash"]

    if current_hash == stored_hash:
        rprint(f"[green]✓ VERIFIED: {rel_path}[/green]" if RICH_AVAILABLE else f"✓ VERIFIED: {rel_path}")
        rprint(f"  Hash matches: {current_hash[:16]}...")
        rprint(f"  Anchored: {registry['files'][rel_path]['anchored_at'][:10]}")

        # Try to verify with OTS
        proof_file = anchor_dir / registry["files"][rel_path]["proof_file"]
        if proof_file.exists():
            success, output = run_ots_command(["verify", str(proof_file)])
            if "Pending" in output:
                rprint("[yellow]  Bitcoin: Pending confirmation[/yellow]" if RICH_AVAILABLE else "  Bitcoin: Pending")
            elif success:
                rprint("[green]  Bitcoin: Confirmed![/green]" if RICH_AVAILABLE else "  Bitcoin: Confirmed!")
    else:
        rprint(f"[red]✗ MODIFIED: {rel_path}[/red]" if RICH_AVAILABLE else f"✗ MODIFIED: {rel_path}")
        rprint(f"  Original: {stored_hash[:16]}...")
        rprint(f"  Current:  {current_hash[:16]}...")
        rprint("")
        rprint("[yellow]File has changed since anchoring![/yellow]" if RICH_AVAILABLE else "File has changed!")
        rprint("Run: anchor commit " + rel_path + " (to anchor new version)")
        sys.exit(1)


@cli.command()
def history():
    """Show history of all anchored files."""
    anchor_dir = get_anchor_dir()

    if not anchor_dir.exists():
        rprint("[red]Error: Not an anchor repository.[/red]" if RICH_AVAILABLE else "Error: Not an anchor repository.")
        sys.exit(1)

    registry = load_registry(anchor_dir)

    if not registry["files"]:
        rprint("[yellow]No files anchored yet.[/yellow]" if RICH_AVAILABLE else "No files anchored yet.")
        return

    # Sort by date
    sorted_files = sorted(
        registry["files"].items(),
        key=lambda x: x[1]["anchored_at"],
        reverse=True
    )

    rprint("\n[bold]⚓ Anchor History[/bold]\n" if RICH_AVAILABLE else "\n⚓ Anchor History\n")

    for filepath, info in sorted_files:
        rprint(f"[cyan]{info['anchored_at'][:19]}[/cyan]" if RICH_AVAILABLE else info['anchored_at'][:19])
        rprint(f"  {filepath}")
        rprint(f"  [dim]{info['hash'][:32]}...[/dim]" if RICH_AVAILABLE else f"  {info['hash'][:32]}...")
        if info.get("message"):
            rprint(f"  [italic]\"{info['message']}\"[/italic]" if RICH_AVAILABLE else f"  \"{info['message']}\"")
        rprint("")


@cli.command()
@click.argument("file", type=click.Path(exists=True))
def info(file):
    """Show detailed info about an anchored file."""
    anchor_dir = get_anchor_dir()

    if not anchor_dir.exists():
        rprint("[red]Error: Not an anchor repository.[/red]" if RICH_AVAILABLE else "Error: Not an anchor repository.")
        sys.exit(1)

    registry = load_registry(anchor_dir)
    path = Path(file)
    # Security: Safe relative_to with fallback
    try:
        if path.is_absolute():
            rel_path = str(path.resolve().relative_to(Path.cwd().resolve()))
        else:
            rel_path = str(path)
    except (ValueError, OSError):
        rel_path = str(path)

    if rel_path not in registry["files"]:
        rprint(f"[yellow]File not anchored: {rel_path}[/yellow]" if RICH_AVAILABLE else f"File not anchored: {rel_path}")
        sys.exit(1)

    info = registry["files"][rel_path]

    rprint(f"\n[bold]⚓ {rel_path}[/bold]\n" if RICH_AVAILABLE else f"\n⚓ {rel_path}\n")
    rprint(f"SHA256:     {info['hash']}")
    rprint(f"Anchored:   {info['anchored_at']}")
    rprint(f"Status:     {info['status']}")
    rprint(f"Proof:      {info['proof_file']}")
    if info.get("message"):
        rprint(f"Note:       {info['message']}")
    if info.get("calendars"):
        rprint(f"Calendars:  {', '.join(info['calendars'])}")


@cli.command()
def upgrade():
    """Check and upgrade pending anchors to confirmed status."""
    anchor_dir = get_anchor_dir()

    if not anchor_dir.exists():
        error_exit("Not an anchor repository. Run 'anchor init' first.")

    registry = load_registry(anchor_dir)

    if not registry["files"]:
        warn("No files anchored yet.")
        return

    pending_count = 0
    already_confirmed_count = 0
    newly_confirmed_count = 0
    updated = False

    for filepath, file_info in registry["files"].items():
        if file_info.get("status") == "pending":
            pending_count += 1
            proof_file = anchor_dir / file_info["proof_file"]

            if proof_file.exists():
                # Try to upgrade the proof
                ots_success, output = run_ots_command(["upgrade", str(proof_file)])

                # Check verification status
                verify_success, verify_output = run_ots_command(["verify", str(proof_file)])

                if "Bitcoin block" in verify_output and "Pending" not in verify_output:
                    file_info["status"] = "confirmed"
                    updated = True
                    newly_confirmed_count += 1
                    success(f"✓ Confirmed: {filepath}")
                else:
                    rprint(f"⏳ Still pending: {filepath}")
        else:
            already_confirmed_count += 1

    if updated:
        save_registry(anchor_dir, registry)

    total_confirmed = already_confirmed_count + newly_confirmed_count
    still_pending = pending_count - newly_confirmed_count

    rprint("")
    rprint(f"Summary: {total_confirmed} confirmed, {still_pending} still pending")

    if still_pending > 0:
        rprint("[dim]Bitcoin confirmations typically take 1-2 hours.[/dim]" if RICH_AVAILABLE else "Bitcoin confirmations typically take 1-2 hours.")


if __name__ == "__main__":
    cli()
