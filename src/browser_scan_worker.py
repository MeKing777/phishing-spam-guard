"""stdin/stdout bridge from the desktop browser to local Python checks."""
from __future__ import annotations

import json
import sys

from src.analyzer import analyze_email, analyze_url
from src.ollama_client import explain_with_ollama


def handle(request: dict) -> object:
    mode = request.get("mode")
    if mode == "url":
        return analyze_url(str(request.get("url", "")))
    if mode == "links":
        return [analyze_url(str(url)) for url in request.get("urls", [])[:80] if str(url).strip()]
    if mode == "email":
        fields = request.get("email", {})
        allowed = {"subject", "sender", "reply_to", "body", "sender_name", "link_pairs"}
        result = analyze_email(**{key: fields[key] for key in allowed if key in fields})
        checked_links = []
        for link in fields.get("link_pairs", [])[:20]:
            href = str(link.get("href", "")).strip()
            if not href or any(item["url"] == href for item in checked_links):
                continue
            checked_links.append(analyze_url(href))
        result["urls"] = checked_links
        suspicious = [item for item in checked_links if item["risk_level"] in {"High", "Review"}]
        if suspicious:
            strongest = max(item["risk_score"] for item in suspicious)
            result["risk_score"] = min(100, result["risk_score"] + min(35, round(strongest * 0.45)))
            result["risk_level"] = "High" if result["risk_score"] >= 60 else "Review" if result["risk_score"] >= 30 else "Low"
            result["category"] = "Phishing" if result["category"] == "No obvious match" else result["category"]
            result["signals"].append(f"Contains {len(suspicious)} link destination(s) with URL warning signs (highest score: {strongest}/100)")
        return result
    if mode == "ollama-email":
        fields = request.get("email", {})
        if not isinstance(fields, dict):
            raise ValueError("Email content is invalid")
        links = fields.get("link_pairs", [])
        link_text = "\n".join(
            f"- {str(item.get('text', '')).strip()[:160]}: {str(item.get('href', '')).strip()[:1000]}"
            for item in links[:20]
            if isinstance(item, dict)
        ) if isinstance(links, list) else ""
        email_text = (
            f"Subject: {str(fields.get('subject', ''))[:250]}\n"
            f"From: {str(fields.get('sender_name', ''))[:120]} <{str(fields.get('sender', ''))[:320]}>\n\n"
            f"{str(fields.get('body', ''))[:12000]}\n\n"
            f"Links:\n{link_text}"
        )
        model = str(request.get("model", "llama3.2:3b"))[:100]
        return explain_with_ollama(email_text, model=model)
    raise ValueError("Unsupported scan request")


for line in sys.stdin:
    try:
        message = json.loads(line)
        response = {"id": message.get("id"), "result": handle(message.get("request", {}))}
    except Exception as exc:
        response = {"id": message.get("id"), "error": " ".join(str(exc).split())[:300]}
    print(json.dumps(response, ensure_ascii=False), flush=True)
