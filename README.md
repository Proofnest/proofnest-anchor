# PROOFNEST ANCHOR

**Git commit for your IP.**

Timestamp files to Bitcoin in seconds. Prove prior art. Forever.

## Installation

```bash
pip install proofnest-anchor
```

Also requires OpenTimestamps client:
```bash
pip install opentimestamps-client
```

## Quick Start

```bash
# Initialize in your project
anchor init

# Timestamp a file
anchor commit important-idea.md

# Check status
anchor status

# Verify file hasn't changed
anchor verify important-idea.md
```

## Commands

| Command | Description |
|---------|-------------|
| `anchor init` | Initialize `.anchor/` directory |
| `anchor commit <file>` | Timestamp file to Bitcoin |
| `anchor commit --all` | Timestamp all files matching config |
| `anchor commit --staged` | Timestamp git staged files |
| `anchor status` | Show pending/confirmed anchors |
| `anchor verify <file>` | Verify file hasn't changed |
| `anchor history` | Show all anchored files |
| `anchor upgrade` | Upgrade pending to confirmed |

## How It Works

1. You run `anchor commit myfile.py`
2. SHA256 hash is calculated
3. Hash is submitted to Bitcoin via OpenTimestamps
4. Proof file saved to `.anchor/proofs/`
5. ~1-2 hours later: Bitcoin block confirms your timestamp

## Why?

- **Prior Art**: Prove you created something at a specific time
- **IP Protection**: Timestamp your ideas, code, designs
- **Legal Evidence**: Bitcoin-backed cryptographic proof
- **Forever**: Bitcoin blockchain is permanent

## License

Apache-2.0. Copyright (c) 2025 Stellanium Ltd.

PROOFNEST is a trademark of Stellanium Ltd.
