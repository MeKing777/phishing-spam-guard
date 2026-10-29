"""Create unpacked Alerter packages for Chromium browsers and Firefox."""
from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ICON_DIR = ROOT / "icons"
OUTPUTS = {
    "chromium": ROOT / "build" / "chromium",
    "firefox": ROOT / "build" / "firefox",
}
ARCHIVES = {
    "chromium": ROOT / "build" / "Alerter-Chromium",
    "firefox": ROOT / "build" / "Alerter-Firefox",
}
SHARED_FILES = (
    "background.js", "content.js", "popup.html", "popup.js", "setup.html",
    "popup-guard.js", "threat-intel.js",
)


def write_icons() -> None:
    """Keep the supplied Alerter brand icons intact and verify their dimensions."""
    for size in (16, 48, 128):
        icon = ICON_DIR / f"alerter-{size}.png"
        if not icon.is_file():
            raise FileNotFoundError(f"Missing Alerter icon: {icon}")
        with icon.open("rb") as image:
            header = image.read(24)
        if len(header) < 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError(f"Alerter icon is not a PNG image: {icon}")
        width, height = struct.unpack(">II", header[16:24])
        if (width, height) != (size, size):
            raise ValueError(f"Alerter icon must be {size} x {size}: {icon} is {width} x {height}")


def build() -> None:
    write_icons()
    for browser, output in OUTPUTS.items():
        output.mkdir(parents=True, exist_ok=True)
        for filename in SHARED_FILES:
            shutil.copy2(ROOT / filename, output / filename)
        shutil.copytree(ICON_DIR, output / "icons", dirs_exist_ok=True)
        shutil.copytree(ROOT / "rules", output / "rules", dirs_exist_ok=True)
        manifest = json.loads((ROOT / f"manifest.{browser}.json").read_text(encoding="utf-8"))
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"{browser}: {output}")
        archive_base = ARCHIVES[browser]
        archive_base.parent.mkdir(parents=True, exist_ok=True)
        archive = shutil.make_archive(str(archive_base), "zip", root_dir=output)
        print(f"{browser} zip: {archive}")


if __name__ == "__main__":
    build()
