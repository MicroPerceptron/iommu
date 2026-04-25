#!/usr/bin/env python3
"""Switch rust-analyzer's cargo target for cross-arch cfg checking.

Usage:
    tools/ra-target.py x86       # x86_64-unknown-none
    tools/ra-target.py aarch64   # aarch64-unknown-none
    tools/ra-target.py riscv     # riscv64gc-unknown-none-elf
    tools/ra-target.py host      # remove target override (use host default)
    tools/ra-target.py           # show current target
"""

import json
import sys
from pathlib import Path

TARGETS = {
    "x86": "x86_64-unknown-none",
    "x86_64": "x86_64-unknown-none",
    "aarch64": "aarch64-unknown-none",
    "arm64": "aarch64-unknown-none",
    "riscv": "riscv64gc-unknown-none-elf",
    "riscv64": "riscv64gc-unknown-none-elf",
    "host": None,
}

RA_TARGET_KEY = "rust-analyzer.cargo.target"
RA_CHECK_CMD_KEY = "rust-analyzer.check.overrideCommand"


def check_command(target: str) -> list[str]:
    """Build the cargo check command RA should use for a kernel target.

    When targeting a freestanding triple, only the root `iommu` package can
    compile — workspace members like kspec/kmain depend on std.  Limiting
    the check to `-p iommu` prevents RA from failing on those crates.
    """
    return [
        "cargo",
        "check",
        "-p",
        "iommu",
        "--target",
        target,
        "--message-format=json",
    ]


def main():
    project_root = Path(__file__).resolve().parent.parent
    settings_path = project_root / ".vscode" / "settings.json"

    if not settings_path.exists():
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings = {}
    else:
        settings = json.loads(settings_path.read_text())

    if len(sys.argv) < 2:
        current = settings.get(RA_TARGET_KEY)
        if current:
            print(f"current: {current}")
        else:
            print("current: host (no target override)")
        print(
            f"\navailable: {', '.join(sorted(set(TARGETS.values()) - {None}))}"  # type: ignore
        )
        return

    alias = sys.argv[1].lower()
    if alias not in TARGETS:
        print(f"unknown target '{alias}'", file=sys.stderr)
        print(f"available: {', '.join(sorted(TARGETS.keys()))}", file=sys.stderr)
        sys.exit(1)

    target = TARGETS[alias]

    if target is None:
        settings.pop(RA_TARGET_KEY, None)
        settings.pop(RA_CHECK_CMD_KEY, None)
        print("rust-analyzer target: host (removed override)")
    else:
        settings[RA_TARGET_KEY] = target
        settings[RA_CHECK_CMD_KEY] = check_command(target)
        print(f"rust-analyzer target: {target}")

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    print(
        "restart rust-analyzer to apply (cmd+shift+p → 'Rust Analyzer: Restart Server')"
    )


if __name__ == "__main__":
    main()
