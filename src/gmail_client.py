"""Gmail OAuth and message operations for the local application."""

from __future__ import annotations

import base64
import re
from email.header import decode_header
from html.parser import HTMLParser
from email.utils import parseaddr
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS_PATH = PROJECT_ROOT / "credentials.json"
TOKEN_PATH = PROJECT_ROOT / "token.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


class _EmailHTMLText(HTMLParser):
    """Keep visible email text and link destinations from HTML-only messages."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output: list[str] = []
        self.links: list[str] = []
        self.link_pairs: list[dict] = []
        self.ignored_depth = 0
        self.active_link: dict | None = None

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.ignored_depth += 1
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href:
                self.links.append(href)
                self.output.append(f" {href} ")
                self.active_link = {"href": href, "text": []}

    def handle_endtag(self, tag):
        if tag == "a" and self.active_link:
            self.link_pairs.append({
                "href": self.active_link["href"],
                "text": " ".join(self.active_link["text"]).strip(),
            })
            self.active_link = None
        if tag in {"script", "style"} and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data):
        if not self.ignored_depth:
            self.output.append(data)
            if self.active_link:
                self.active_link["text"].append(data)


def connect_gmail():
    """Authorize the local app and return a Gmail API service."""
    credentials = None
    if TOKEN_PATH.exists():
        credentials = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

    if credentials and credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

    if not credentials or not credentials.valid:
        if not CREDENTIALS_PATH.exists():
            raise FileNotFoundError(
                "Google OAuth credentials were not found. Follow the Gmail setup steps in README.md, "
                "then place the downloaded Desktop OAuth file in the project folder as credentials.json."
            )
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_PATH), SCOPES)
        credentials = flow.run_local_server(port=0, open_browser=True)
        TOKEN_PATH.write_text(credentials.to_json(), encoding="utf-8")

    return build("gmail", "v1", credentials=credentials, cache_discovery=False)


def _decode_body(data: str) -> str:
    padded = data + "=" * (-len(data) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    return raw.decode("utf-8", errors="replace")


def _decode_header_value(value: str) -> str:
    decoded_parts = []
    for part, encoding in decode_header(value or ""):
        if isinstance(part, bytes):
            decoded_parts.append(part.decode(encoding or "utf-8", errors="replace"))
        else:
            decoded_parts.append(part)
    return "".join(decoded_parts)


def _collect_message_parts(part: dict, plain: list[str], html: list[str], attachments: list[str]) -> None:
    filename = _decode_header_value(part.get("filename", "")).strip()
    if filename and filename not in attachments:
        attachments.append(filename)
    mime_type = part.get("mimeType", "")
    data = part.get("body", {}).get("data")
    if data:
        decoded = _decode_body(data)
        if mime_type == "text/plain":
            plain.append(decoded)
        elif mime_type == "text/html":
            html.append(decoded)
    for child in part.get("parts", []):
        _collect_message_parts(child, plain, html, attachments)


def _message_content(payload: dict) -> tuple[str, list[dict], list[str]]:
    plain: list[str] = []
    html: list[str] = []
    attachments: list[str] = []
    _collect_message_parts(payload, plain, html, attachments)
    parser = _EmailHTMLText()
    if html:
        parser.feed("\n".join(html))
        parser.close()
    if plain:
        hidden_destinations = "\n".join(parser.links)
        body = "\n".join(part for part in ("\n".join(plain), hidden_destinations) if part)
        return body, parser.link_pairs, attachments
    if html:
        return " ".join(parser.output), parser.link_pairs, attachments
    return "", parser.link_pairs, attachments


def _message_body(payload: dict) -> str:
    """Return readable message text, preserving link destinations for URL checks."""
    return _message_content(payload)[0]


def fetch_inbox(service, limit: int = 25, query: str = "in:inbox newer_than:30d") -> list[dict]:
    """Fetch recent inbox messages and their text for local analysis."""
    listed = service.users().messages().list(userId="me", q=query, maxResults=limit).execute()
    messages = []
    for entry in listed.get("messages", []):
        full = service.users().messages().get(userId="me", id=entry["id"], format="full").execute()
        raw_headers = full.get("payload", {}).get("headers", [])
        headers = {item.get("name", "").lower(): item.get("value", "") for item in raw_headers}
        sender_name, sender_address = parseaddr(_decode_header_value(headers.get("from", "")))
        _, reply_address = parseaddr(_decode_header_value(headers.get("reply-to", "")))
        _, return_path_address = parseaddr(_decode_header_value(headers.get("return-path", "")))
        auth_values = [
            item.get("value", "")
            for item in raw_headers
            if item.get("name", "").lower() in {"authentication-results", "arc-authentication-results"}
        ]
        google_auth_values = [value for value in auth_values if re.match(r"\s*mx\.google\.com\s*;", value, re.I)]
        authentication_results = "\n".join(google_auth_values or auth_values)
        body, link_pairs, attachment_names = _message_content(full.get("payload", {}))
        messages.append({
            "id": full["id"],
            "thread_id": full.get("threadId", ""),
            "subject": _decode_header_value(headers.get("subject", "(No subject)")),
            "sender": sender_address or headers.get("from", "Unknown sender"),
            "sender_name": sender_name,
            "reply_to": reply_address,
            "return_path": return_path_address,
            "authentication_results": authentication_results,
            "link_pairs": link_pairs,
            "attachment_names": attachment_names,
            "date": headers.get("date", ""),
            "snippet": full.get("snippet", ""),
            "body": body,
        })
    return messages


def move_to_spam(service, message_id: str) -> None:
    service.users().messages().modify(
        userId="me", id=message_id,
        body={"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
    ).execute()


def move_to_trash(service, message_id: str) -> None:
    service.users().messages().trash(userId="me", id=message_id).execute()


def disconnect_gmail() -> None:
    """Remove the locally saved OAuth token. The user can also revoke access in Google Account settings."""
    if TOKEN_PATH.exists():
        TOKEN_PATH.unlink()

