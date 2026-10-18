"""Loopback-only API for the Alerter browser extension (stdlib only)."""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from src.analyzer import analyze_email, analyze_url


HOST = "127.0.0.1"
PORT = 8766
MAX_REQUEST_BYTES = 5_600_000
MAX_SCREEN_BYTES = 4_000_000
SCREEN_IMAGE_PATTERN = re.compile(r"^data:image/(jpeg|png);base64,([A-Za-z0-9+/=\r\n]+)$")
EXTENSION_ORIGINS = (
    re.compile(r"^chrome-extension://[a-p]{32}$"),
    re.compile(r"^moz-extension://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
)


def find_tesseract() -> str | None:
    configured = os.environ.get("ALERTER_TESSERACT_PATH", "").strip().strip('"')
    if configured and Path(configured).is_file():
        return configured
    discovered = shutil.which("tesseract")
    if discovered:
        return discovered
    if os.name == "nt":
        standard_install = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tesseract-OCR" / "tesseract.exe"
        if standard_install.is_file():
            return str(standard_install)
    return None


def analyze_screen(image_data_url: str) -> dict:
    """OCR one user-requested screenshot locally, then score only its extracted text."""
    match = SCREEN_IMAGE_PATTERN.fullmatch(image_data_url or "")
    if not match:
        raise ValueError("The screenshot format was not recognized. Please try again.")
    image_type, encoded = match.groups()
    try:
        image_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("The screenshot data was invalid. Please try again.") from exc
    if not image_bytes or len(image_bytes) > MAX_SCREEN_BYTES:
        raise ValueError("The screenshot is empty or too large. Try zooming out or reducing the browser window size.")

    executable = find_tesseract()
    if not executable:
        raise RuntimeError("Screen scanning needs Tesseract OCR installed on this computer. Install Tesseract, restart the Alerter checker, and try again.")

    suffix = ".jpg" if image_type == "jpeg" else ".png"
    with tempfile.TemporaryDirectory(prefix="alerter-screen-") as temp_dir:
        image_path = Path(temp_dir) / f"visible-screen{suffix}"
        image_path.write_bytes(image_bytes)
        try:
            process = subprocess.run(
                [executable, str(image_path), "stdout", "-l", "eng", "--psm", "11"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=25,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Reading this screen took too long. Try a smaller browser window and scan again.") from exc
        except OSError as exc:
            raise RuntimeError("Alerter could not start the local OCR program. Check the Tesseract installation and try again.") from exc

    if process.returncode != 0:
        raise RuntimeError("Tesseract could not read this screenshot. Check that its English language data is installed.")
    text = process.stdout[:20000].strip()
    if len(re.sub(r"\s", "", text)) < 12:
        return {
            "risk_score": 0,
            "risk_level": "Review",
            "category": "Not enough readable text",
            "signals": ["Alerter could not read enough text from this screenshot to check it", "Try zooming in on the text and scan the visible screen again"],
            "urls": [],
            "source_label": "Visible screen · local OCR",
            "notice": "A screenshot with unreadable text is not a safe result.",
        }

    result = analyze_email(body=text)
    result["source_label"] = f"Visible screen · local OCR · {len(text)} characters read"
    result["notice"] = "Only text detected in the visible screenshot was checked. A low risk result is not proof that the page is safe."
    return result


def is_allowed_extension_origin(origin: str) -> bool:
    return any(pattern.fullmatch(origin) for pattern in EXTENSION_ORIGINS)


class GuardHandler(BaseHTTPRequestHandler):
    server_version = "Alerter/1"

    def log_message(self, format: str, *args: object) -> None:
        print("Alerter local checker:", format % args, flush=True)

    def _headers(self, status: int, origin: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if is_allowed_extension_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json(self, status: int, payload: object) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        origin = self.headers.get("Origin", "")
        self._headers(status, origin)
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self._headers(204, self.headers.get("Origin", ""))

    def do_GET(self) -> None:
        if self.path != "/health":
            self._json(404, {"error": "Not found"})
            return
        self._json(200, {
            "status": "ok",
            "message": "Local link and email checker is running",
            "screen_ocr_available": find_tesseract() is not None,
        })

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAX_REQUEST_BYTES:
                self._json(413, {"error": "Request is empty or too large"})
                return
            payload = json.loads(self.rfile.read(length))
            if self.path == "/analyze-url":
                url = str(payload.get("url", "")).strip()
                if not url or len(url) > 4096:
                    raise ValueError("Enter a web address up to 4096 characters")
                result = analyze_url(url)
            elif self.path == "/analyze-links":
                urls = payload.get("urls", [])
                if not isinstance(urls, list):
                    raise ValueError("Links must be a list")
                result = [analyze_url(str(url)[:4096]) for url in urls[:100] if str(url).strip()]
            elif self.path == "/analyze-email":
                email = payload.get("email", {})
                if not isinstance(email, dict):
                    raise ValueError("Email content is invalid")
                allowed = {"subject", "sender", "reply_to", "body", "sender_name", "link_pairs"}
                fields = {key: email[key] for key in allowed if key in email}
                result = analyze_email(**fields)
                links = email.get("link_pairs", [])
                checked = []
                seen = set()
                for item in links[:20] if isinstance(links, list) else []:
                    href = str(item.get("href", "")).strip()[:4096]
                    if href and href not in seen:
                        seen.add(href)
                        checked.append(analyze_url(href))
                result["urls"] = checked
                suspicious = [item for item in checked if item["risk_level"] in {"High", "Review"}]
                if suspicious:
                    strongest = max(item["risk_score"] for item in suspicious)
                    result["risk_score"] = min(100, result["risk_score"] + min(35, round(strongest * 0.45)))
                    score = result["risk_score"]
                    result["risk_level"] = "High" if score >= 60 else "Review" if score >= 30 else "Low"
                    result["category"] = "Phishing" if result["category"] == "No obvious match" else result["category"]
                    result["signals"].append(f"Contains {len(suspicious)} link destination(s) with URL warning signs (highest score: {strongest}/100)")
            elif self.path == "/analyze-screen":
                image_data_url = payload.get("image_data_url", "")
                if not isinstance(image_data_url, str):
                    raise ValueError("Screenshot data is invalid")
                result = analyze_screen(image_data_url)
            else:
                self._json(404, {"error": "Not found"})
                return
            self._json(200, result)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)[:240]})
        except RuntimeError as exc:
            self._json(503, {"error": str(exc)[:240]})
        except Exception as exc:
            self._json(500, {"error": f"Local check failed: {str(exc)[:180]}"})


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), GuardHandler)
    print(f"Alerter local checker listening on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
