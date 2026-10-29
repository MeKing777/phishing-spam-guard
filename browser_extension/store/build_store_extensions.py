"""Build self-contained browser-store ZIPs for Chromium and Firefox."""
from __future__ import annotations

import json
import shutil
from pathlib import Path


STORE_ROOT = Path(__file__).resolve().parent
EXTENSION_ROOT = STORE_ROOT.parent
BUILD_ROOT = STORE_ROOT / "build"
SHARED_FILES = ("content.js", "popup.html", "popup.js", "popup-guard.js")


def build() -> None:
    icons = EXTENSION_ROOT / "icons"
    for browser in ("chromium", "firefox"):
        output = BUILD_ROOT / browser
        if output.exists():
            shutil.rmtree(output)
        output.mkdir(parents=True)
        for filename in SHARED_FILES:
            shutil.copy2(EXTENSION_ROOT / filename, output / filename)
        for filename in ("analyzer.js", "background.js"):
            shutil.copy2(STORE_ROOT / filename, output / filename)
        shutil.copy2(EXTENSION_ROOT / "threat-intel.js", output / "threat-intel.js")
        shutil.copytree(icons, output / "icons")
        shutil.copytree(EXTENSION_ROOT / "rules", output / "rules")
        manifest = json.loads((STORE_ROOT / f"manifest.{browser}.json").read_text(encoding="utf-8"))
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        archive = BUILD_ROOT / f"Alerter-{browser.title()}-Store.zip"
        if archive.exists():
            archive.unlink()
        shutil.make_archive(str(archive.with_suffix("")), "zip", root_dir=output)
        release = STORE_ROOT / f"Alerter-{browser.title()}-Store-{manifest['version']}.zip"
        shutil.copy2(archive, release)
        print(f"{browser}: {output}")
        print(f"zip: {archive}")
        print(f"release: {release}")


if __name__ == "__main__":
    build()
