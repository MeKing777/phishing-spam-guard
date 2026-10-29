"""Transparent, local-first heuristics for email and URL triage."""

from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from html import unescape
from urllib.parse import parse_qsl, unquote, urlsplit

from src.trained_detector import assess as assess_trained_model
from src.threat_intel import lookup_host


URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
TRAILING_URL_PUNCTUATION = ").,!?;:]}'\""

PHISHING_PATTERNS = (
    (re.compile(r"\b(verify|confirm|restore|unlock|suspend(?:ed)?|secure)\b.{0,55}\b(account|password|identity|payment|mailbox)\b", re.I), 18, "Urgent account or identity verification language"),
    (re.compile(r"\b(password|login|sign in|credentials|one[- ]time code|security code)\b.{0,70}\b(click|link|reply|confirm|verify|submit|send)\b", re.I), 25, "Asks for credentials or a security code"),
    (re.compile(r"\b(click|tap|follow)\b.{0,35}\b(link|here|below)\b", re.I), 8, "Pressures the reader to follow a link"),
    (re.compile(r"\b(?:invoice|wire transfer|bank account|bank transfer|payment|crypto(?:currency)?|wallet)\b.{0,55}\b(?:overdue|past due|required|failed|confirm|verify|update|pay|send|transfer|settle)\b|\b(?:pay|send|transfer|confirm|verify|update|settle)\b.{0,55}\b(?:invoice|bank account|bank transfer|payment|crypto(?:currency)?|wallet)\b", re.I), 12, "Requests or discusses a sensitive payment action"),
)

SPAM_PATTERNS = (
    (re.compile(r"\b(?:you(?:'|’)ve won|winner|prize|gift card|giveaway|free entry|claim (?:your|a|an|the) (?:free )?(?:prize|gift|reward|voucher)|win (?:a|the) (?:free )?(?:prize|gift|reward|voucher))\b", re.I), 18, "Prize, giveaway, or free-reward language"),
    (re.compile(r"\b(earn money|make money fast|guaranteed income|work from home|get rich)\b", re.I), 16, "Unsolicited income or guaranteed-return language"),
    (re.compile(r"\b(?:limited[- ]time offer|act now|urgent|expires today|last chance)\b", re.I), 8, "Creates urgency to prompt a quick response"),
    (re.compile(r"\b(?:buy now|order now|special offer|discount|sale ends|promotional offer)\b", re.I), 6, "Promotional or bulk-message language"),
)

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at"
}
REDIRECT_PARAMS = {
    "url", "u", "target", "destination", "redirect", "redirecturl", "redirecturi",
    "redir", "next", "continue", "continueurl", "continueuri", "return", "returnto",
    "returnurl", "returnuri", "out", "to", "link", "goto", "forward", "forwardurl",
}

BRAND_DOMAINS = {
    "adobe": ("adobe.com",),
    "amazon": ("amazon.com",),
    "apple": ("apple.com", "icloud.com"),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com",),
    "google": ("google.com", "gmail.com", "googlemail.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com", "paypalobjects.com"),
    "yahoo": ("yahoo.com",),
}

FREE_EMAIL_DOMAINS = {
    "aol.com", "gmail.com", "googlemail.com", "hotmail.com", "icloud.com", "live.com",
    "outlook.com", "yahoo.com",
}

RISKY_ATTACHMENT_EXTENSIONS = {
    ".ade", ".adp", ".app", ".bat", ".cab", ".cmd", ".com", ".cpl", ".exe",
    ".hta", ".img", ".iso", ".jar", ".js", ".jse", ".lnk", ".msi", ".ps1",
    ".scr", ".vbe", ".vbs", ".wsf", ".wsh",
}
REVIEW_ATTACHMENT_EXTENSIONS = {
    ".docm", ".dotm", ".html", ".htm", ".iso", ".pptm", ".xlam", ".xlsm", ".xltm",
}
RISKY_DOWNLOAD_EXTENSIONS = {
    ".apk", ".app", ".bat", ".cmd", ".com", ".dmg", ".exe", ".hta", ".jar",
    ".js", ".lnk", ".msi", ".pkg", ".ps1", ".scr", ".vbs",
}
REVIEW_DOWNLOAD_EXTENSIONS = {".docm", ".iso", ".img", ".pptm", ".xlsm", ".xlam"}


def _email_domain(address: str) -> str:
    parsed_address = parseaddr(address or "")[1]
    candidate = parsed_address or (address or "")
    return candidate.rsplit("@", 1)[-1].strip(" >.").lower() if "@" in candidate else ""


def _domains_align(first: str, second: str) -> bool:
    return bool(first and second) and (
        first == second or first.endswith("." + second) or second.endswith("." + first)
    )


def _brand_claim(host: str) -> tuple[str, bool, bool] | None:
    """Return a claimed brand, official-domain status, and lookalike status."""
    labels = [piece for label in host.lower().split(".") for piece in label.split("-")]
    substitutions = str.maketrans({"0": "o", "1": "l"})
    normalized_labels = [label.translate(substitutions).replace("rn", "m").replace("vv", "w") for label in labels]
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in labels or brand in normalized_labels:
            official = any(host == domain or host.endswith("." + domain) for domain in official_domains)
            return brand, official, brand not in labels
    return None


def _looks_like_domain(text: str) -> str:
    """Extract a host only when link text itself looks like a web address."""
    candidate = (text or "").strip().strip("<>()[]{}.,;\"'")
    if not re.match(r"(?i)^(?:https?://|www\.)", candidate) and not re.match(
        r"(?i)^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[/?#]|$)", candidate
    ):
        return ""
    try:
        return (_parse_url(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _auth_header_findings(authentication_results: str) -> list[tuple[str, int, str]]:
    """Turn reported SPF/DKIM/DMARC failures into explainable, bounded signals."""
    findings: list[tuple[str, int, str]] = []
    checks = (
        ("spf", 14, 8, "The email authentication header reports SPF did not pass"),
        ("dkim", 14, 8, "The email authentication header reports DKIM did not pass"),
        ("dmarc", 22, 10, "The email authentication header reports DMARC did not pass"),
    )
    for method, fail_points, softfail_points, label in checks:
        match = re.search(rf"(?<![a-z0-9_-]){method}\s*=\s*([a-z]+)", authentication_results or "", re.I)
        if not match:
            continue
        status = match.group(1).lower()
        if status in {"fail", "permerror"}:
            findings.append((method, fail_points, label))
        elif status == "softfail":
            findings.append((method, softfail_points, f"The email authentication header reports a {method.upper()} soft failure"))
    return findings


def _is_aws_credly_badge_notice(
    sender_domain: str, sender_name: str, subject: str, body: str
) -> bool:
    """Recognize a narrow, common legitimate AWS badge-delivery pattern."""
    domain = (sender_domain or "").lower().rstrip(".")
    if domain != "credly.com" and not domain.endswith(".credly.com"):
        return False
    display = unescape(sender_name or "")
    content = unescape(f"{subject or ''} {body or ''}")
    return bool(
        re.search(r"\bamazon\b", display, re.I)
        and re.search(r"\b(?:amazon web services|aws)\b", content, re.I)
        and re.search(r"\b(?:training|certification|educate|course)\b", f"{display} {content}", re.I)
        and re.search(
            r"\b(?:earned|awarded|received|completed|issued)\b.{0,80}\b(?:badge|certificate|credential|certification)\b",
            content,
            re.I,
        )
    )


def _is_aws_badge_related_host(host: str) -> bool:
    candidate = (host or "").lower().rstrip(".")
    return any(
        candidate == domain or candidate.endswith("." + domain)
        for domain in ("credly.com", "amazon.com", "amazonaws.com")
    )


def extract_urls(text: str) -> list[str]:
    """Return URLs found in text without following or fetching them."""
    urls: list[str] = []
    for match in URL_PATTERN.findall(text or ""):
        candidate = match.rstrip(TRAILING_URL_PUNCTUATION)
        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls


def _parse_url(url: str):
    candidate = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I):
        candidate = "https://" + candidate
    return urlsplit(candidate)


def analyze_url(url: str, _depth: int = 0) -> dict:
    """Score visible URL traits without visiting it or inspecting downloaded files."""
    signals: list[str] = []
    score = 0
    raw_url = str(url or "").strip()
    scheme_match = re.match(r"^([a-z][a-z0-9+.-]*):", raw_url, re.I)
    if scheme_match and scheme_match.group(1).lower() in {"javascript", "data", "vbscript"}:
        scheme = scheme_match.group(1).lower()
        return {
            "url": raw_url,
            "host": "Unknown",
            "risk_score": 75,
            "risk_level": "High",
            "signals": [f"Link uses the unsafe {scheme}: scheme instead of a normal web address"],
        }
    try:
        parsed = _parse_url(url)
        raw_host = (parsed.hostname or "").lower().rstrip(".")
        host = raw_host.encode("idna").decode("ascii").lower()
    except ValueError:
        parsed, host = None, ""
    except UnicodeError:
        parsed, host = None, ""

    if not host:
        return {
            "url": url,
            "host": "Unknown",
            "risk_score": 35,
            "risk_level": "Review",
            "signals": ["The address could not be parsed as a normal web URL"],
        }

    if len(url) >= 100:
        score += 15
        signals.append("Unusually long web address")
    elif len(url) >= 75:
        score += 8
        signals.append("Long web address")

    try:
        ipaddress.ip_address(host)
        score += 30
        signals.append("Uses a raw IP address instead of a domain name")
    except ValueError:
        pass

    if parsed and "@" in parsed.netloc:
        score += 30
        signals.append("Contains an @ sign in the address authority")
    if "xn--" in host:
        score += 20
        signals.append("Contains an encoded internationalized domain name")

    brand_claim = _brand_claim(host)
    if brand_claim and not brand_claim[1]:
        brand, _, lookalike = brand_claim
        score += 35 if lookalike else 30
        message = "Resembles" if lookalike else "Uses"
        signals.append(f"{message} the {brand.title()} name on a domain outside its known domains")

    if host in SHORTENER_HOSTS:
        score = max(score + 15, 25)
        signals.append("Uses a link-shortening service that hides the destination")

    labels = host.split(".")
    if len(labels) >= 5:
        score += 12
        signals.append("Contains several nested subdomains")

    if parsed and parsed.scheme.lower() != "https":
        score += 8
        signals.append("Does not use HTTPS")

    suspicious_terms = re.search(r"(?:login|verify|account|secure|password|wallet|payment|signin)", host + parsed.path.lower() if parsed else host)
    if suspicious_terms:
        score += 7
        signals.append("Contains account or payment wording in the domain or path")

    if parsed:
        path = unquote(parsed.path).lower()
        suffix_match = re.search(r"(\.[a-z0-9]{1,10})$", path)
        suffix = suffix_match.group(1) if suffix_match else ""
        if suffix in RISKY_DOWNLOAD_EXTENSIONS:
            score = max(score, 65)
            signals.append(
                f"Direct link to a potentially executable download ({suffix}); this check does not scan the file"
            )
        elif suffix in REVIEW_DOWNLOAD_EXTENSIONS:
            score = max(score, 35)
            signals.append(f"Direct link to a file that may contain active content ({suffix})")

    if parsed and _depth < 2:
        for key, target in parse_qsl(parsed.query, keep_blank_values=False):
            normalized_key = key.lower().replace("_", "").replace("-", "")
            if normalized_key not in REDIRECT_PARAMS or not re.match(r"^https?://", target, re.I):
                continue
            nested = analyze_url(target, _depth + 1)
            if nested["risk_score"] >= 25:
                score = max(score, nested["risk_score"])
                signals.append(
                    f"Redirect parameter points to {nested['host']} ({nested['risk_level']} risk)"
                )
                break

    trained_model = assess_trained_model(url, "url")
    if trained_model and trained_model["flagged"] and trained_model["label"] == "phishing":
        score = max(score, 30)
        signals.append(
            "The locally trained URL model flags this address as phishing "
            f"({trained_model['confidence']:.0%} model score)"
        )
    threat_intel = lookup_host(host)
    if threat_intel:
        score = max(score, 85)
        signals.insert(0, f"Domain appears on the active phishing list maintained by {threat_intel['source']}")
    score = min(score, 100)
    level = "High" if score >= 55 else "Review" if score >= 25 else "Low"
    if not signals:
        signals.append("No obvious URL warning signs found by the local checks")
    result = {"url": url, "host": host, "risk_score": score, "risk_level": level, "signals": signals}
    if threat_intel:
        result["threat_intel"] = threat_intel
    return result


def _risk_level(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Review"
    return "Low"


def analyze_email(
    subject: str = "",
    sender: str = "",
    reply_to: str = "",
    body: str = "",
    sender_name: str = "",
    return_path: str = "",
    authentication_results: str = "",
    attachment_names: list[str] | tuple[str, ...] = (),
    link_pairs: list[dict] | tuple[dict, ...] = (),
) -> dict:
    """Return a transparent risk score for message text and available email evidence."""
    content = unescape(" ".join((subject or "", body or "")))
    signals: list[str] = []
    score = 0
    kinds: set[str] = set()

    sender_domain = _email_domain(sender)
    reply_domain = _email_domain(reply_to)
    return_path_domain = _email_domain(return_path)
    aws_credly_badge = _is_aws_credly_badge_notice(
        sender_domain, sender_name, subject, body
    )
    if aws_credly_badge:
        signals.append(
            "AWS course-badge wording from a Credly address matched; generic reward wording is downweighted, but the sender and links are not verified"
        )

    for pattern, points, label in PHISHING_PATTERNS:
        if aws_credly_badge and label == "Requests or discusses a sensitive payment action":
            continue
        if pattern.search(content):
            score += points
            signals.append(label)
            kinds.add("Phishing")

    for pattern, points, label in SPAM_PATTERNS:
        if aws_credly_badge:
            continue
        if pattern.search(content):
            score += points
            signals.append(label)
            kinds.add("Spam")
    if sender_domain and reply_domain and not _domains_align(sender_domain, reply_domain):
        score += 25
        signals.append("Reply-to address uses a different domain from the sender")
        kinds.add("Phishing")

    if sender_domain and return_path_domain and not _domains_align(sender_domain, return_path_domain):
        score += 16
        signals.append("Return-Path domain does not align with the sender domain")
        kinds.add("Phishing")

    for method, points, signal in _auth_header_findings(authentication_results):
        score += points
        signals.append(signal)
        kinds.add("Phishing")

    display_name = unescape(sender_name or "")
    for brand, official_domains in BRAND_DOMAINS.items():
        if aws_credly_badge and brand == "amazon":
            continue
        if re.search(rf"\b{re.escape(brand)}\b", display_name, re.I) and (
            sender_domain in FREE_EMAIL_DOMAINS
            or not any(
                sender_domain == domain or sender_domain.endswith("." + domain)
                for domain in official_domains
            )
        ):
            score += 30
            signals.append(
                f"Sender display name claims {brand.title()}, but its email domain is different"
            )
            kinds.add("Phishing")
            break

    link_url_checks: list[dict] = []
    for link in link_pairs[:60]:
        href = str(link.get("href", "")).strip()
        visible_text = str(link.get("text", "")).strip()
        scheme = href.split(":", 1)[0].lower() if ":" in href else ""
        if scheme in {"javascript", "data", "vbscript"}:
            link_url_checks.append(analyze_url(href))
            score += 35
            signals.append(f"Contains an embedded link using the {scheme}: scheme")
            kinds.add("Phishing")
            continue
        visible_host = _looks_like_domain(visible_text)
        destination = analyze_url(href) if re.match(r"(?i)^https?://", href) else None
        if destination:
            link_url_checks.append(destination)
        destination_host = destination["host"] if destination else ""
        if visible_host and destination_host not in {"", "Unknown"} and not _domains_align(
            visible_host, destination_host
        ):
            score += 30
            signals.append(
                f"Visible link text names {visible_host}, but the link points to {destination_host}"
            )
            kinds.add("Phishing")

    for filename in attachment_names:
        extension = re.search(r"(\.[a-z0-9]{1,10})+$", str(filename).lower())
        last_extension = extension.group(1).split(".")[-1] if extension else ""
        suffix = f".{last_extension}" if last_extension else ""
        if suffix in RISKY_ATTACHMENT_EXTENSIONS:
            score += 30
            signals.append(f"Attachment name ends in a potentially dangerous {suffix} file type")
            kinds.add("Phishing")
        elif suffix in REVIEW_ATTACHMENT_EXTENSIONS:
            score += 18
            signals.append(f"Attachment uses an active-content file type ({suffix})")
            kinds.add("Phishing")

    urls = extract_urls(content)
    candidates = [*link_url_checks, *(analyze_url(url) for url in urls[:20])]
    url_checks = []
    seen_url_checks: set[str] = set()
    for item in candidates:
        if item["url"] not in seen_url_checks:
            seen_url_checks.add(item["url"])
            url_checks.append(item)
    if aws_credly_badge and any(
        item["host"] not in {"", "Unknown"} and not _is_aws_badge_related_host(item["host"])
        for item in url_checks
    ):
        score += 25
        signals.append("Badge notice contains a link outside Credly or Amazon domains")
        kinds.add("Phishing")
    if url_checks:
        highest_url_risk = max(item["risk_score"] for item in url_checks)
        if highest_url_risk >= 25:
            score += min(35, round(highest_url_risk * 0.45))
            signals.append(f"Contains a link with URL warning signs (highest URL score: {highest_url_risk}/100)")
            kinds.add("Phishing")
        if any(item.get("threat_intel") for item in url_checks):
            score = max(score, 85)
            signals.insert(0, "A linked domain appears in the active community phishing list")
            kinds.add("Phishing")

    trained_model = assess_trained_model(content, "email")
    if (
        trained_model
        and trained_model["flagged"]
        and trained_model["label"] in {"phishing", "spam"}
        and not (aws_credly_badge and trained_model["label"] == "spam")
    ):
        score = max(score, 30)
        signals.append(
            f"The locally trained email model flags this as {trained_model['label']} "
            f"({trained_model['confidence']:.0%} model score)"
        )
        kinds.add(trained_model["label"].title())
    score = min(score, 100)
    if not signals:
        signals.append("No obvious spam or phishing indicators found by the local checks")
    return {
        "risk_score": score,
        "risk_level": _risk_level(score),
        "category": ", ".join(sorted(kinds)) if kinds else "No obvious match",
        "signals": signals,
        "urls": url_checks,
        "sender": sender,
        "sender_name": sender_name,
        "subject": subject,
        "attachment_names": list(attachment_names),
        "notice": "A Low score is not proof that a message is safe. These checks do not verify sender identity or visit links.",
        "trained_model": trained_model,
    }
