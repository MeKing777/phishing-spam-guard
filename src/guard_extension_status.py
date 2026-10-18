"""Check whether Guard is already loaded in the dedicated Chrome profile."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def normalized(path: str | Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def main() -> None:
    if len(sys.argv) != 3:
        print("not installed")
        return
    preferences = Path(sys.argv[1]) / "Default" / "Preferences"
    if not preferences.is_file():
        print("not installed")
        return
    try:
        data = json.loads(preferences.read_text(encoding="utf-8"))
        entries = data.get("extensions", {}).get("settings", {}).values()
        expected = normalized(sys.argv[2])
        for entry in entries:
            if normalized(entry.get("path", "")) == expected and entry.get("state", 1) != 0:
                print("installed")
                return
    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        pass
    print("not installed")


if __name__ == "__main__":
    main()
