"""Create unpacked Alerter packages for Chromium browsers and Firefox."""
from __future__ import annotations

import json
import shutil
import struct
import zlib
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
SHARED_FILES = ("background.js", "content.js", "popup.html", "popup.js", "setup.html")


def _point_in_polygon(x: float, y: float, polygon: list[tuple[float, float]]) -> bool:
    inside = False
    previous = polygon[-1]
    for current in polygon:
        x1, y1 = previous
        x2, y2 = current
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            inside = not inside
        previous = current
    return inside


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def make_icon(size: int) -> bytes:
    background = (37, 99, 235, 255)
    shield = (255, 255, 255, 255)
    accent = (245, 158, 11, 255)
    pixels = bytearray(size * size * 4)
    radius = 0.21
    shield_polygon = [(0.24, 0.17), (0.76, 0.17), (0.74, 0.57), (0.50, 0.83), (0.26, 0.57)]
    mark_polygon = [(0.45, 0.31), (0.55, 0.31), (0.535, 0.55), (0.465, 0.55)]
    dot_center = (0.50, 0.66)
    dot_radius = 0.045

    for y in range(size):
        for x in range(size):
            nx, ny = (x + 0.5) / size, (y + 0.5) / size
            if (nx < radius and ny < radius and (nx - radius) ** 2 + (ny - radius) ** 2 > radius ** 2) or (
                nx > 1 - radius and ny < radius and (nx - (1 - radius)) ** 2 + (ny - radius) ** 2 > radius ** 2
            ) or (
                nx < radius and ny > 1 - radius and (nx - radius) ** 2 + (ny - (1 - radius)) ** 2 > radius ** 2
            ) or (
                nx > 1 - radius and ny > 1 - radius and (nx - (1 - radius)) ** 2 + (ny - (1 - radius)) ** 2 > radius ** 2
            ):
                continue
            color = background
            if _point_in_polygon(nx, ny, shield_polygon):
                color = shield
            if _point_in_polygon(nx, ny, mark_polygon) or (nx - dot_center[0]) ** 2 + (ny - dot_center[1]) ** 2 <= dot_radius ** 2:
                color = accent
            offset = (y * size + x) * 4
            pixels[offset:offset + 4] = bytes(color)

    scanlines = b"".join(b"\x00" + pixels[y * size * 4:(y + 1) * size * 4] for y in range(size))
    header = struct.pack(">2I5B", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", header) + _png_chunk(b"IDAT", zlib.compress(scanlines, 9)) + _png_chunk(b"IEND", b"")


def write_icons() -> None:
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    for size in (16, 48, 128):
        (ICON_DIR / f"alerter-{size}.png").write_bytes(make_icon(size))


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
