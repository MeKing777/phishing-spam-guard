"""Build a deterministic synthetic dataset for pipeline testing, not production scoring."""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "data" / "threat_intelligence"
DATASET_VERSION = "synthetic-v3"

EMAIL_SUBJECTS = {
    "benign": [
        "Meeting notes from {team}",
        "Your {service} receipt for {month}",
        "Updated schedule for {event}",
        "Document ready for your review",
        "Congratulations on earning your {course} training badge",
        "You just earned an AWS Educate course badge",
    ],
    "spam": [
        "You could win a {prize} today",
        "Special offer: save on {product}",
        "Claim your free {prize}",
        "Last chance for our {percent}% discount",
        "Earn rewards with this limited-time offer",
    ],
    "phishing": [
        "Action required: verify your {account}",
        "Your {service} account will be suspended",
        "Confirm your {account} password now",
        "Unusual sign-in: restore access",
        "Payment failed: secure your account",
    ],
}

EMAIL_BODIES = {
    "benign": [
        "The {team} meeting is scheduled for {weekday}. The agenda is attached to the calendar invite.",
        "Your order from {service} is confirmed. The receipt is available in your account dashboard.",
        "Please review the latest {project} notes before our next scheduled discussion.",
        "The {event} schedule has changed. Contact the organizer through your usual company directory.",
        "Congratulations, you completed the {course} training and earned a badge. View it from your learning account. No payment or password is requested.",
        "You just earned a badge from Amazon Web Services Training and Certification. AWS Educate Getting Started with Security - Training Badge. Issuer: Amazon Web Services Training and Certification.",
    ],
    "spam": [
        "Congratulations, you may claim a {prize}. Limited time offer; visit our promotions page to learn more.",
        "Buy now and save {percent} percent on {product}. Unsubscribe using the preference link if you do not want these offers.",
        "Enter our giveaway for a chance to win a {prize}. Terms and conditions apply to all entries.",
        "Act now to receive a special offer on {product}. This promotional message was sent to subscribers.",
        "You have been selected for a free {prize} drawing. No purchase is necessary; see official rules for details.",
    ],
    "phishing": [
        "Verify your account immediately to avoid suspension. Click the link and submit your password to restore access.",
        "We detected an unusual sign-in. Confirm your identity and security code to keep your mailbox active.",
        "Your payment is overdue. Follow the link to secure your account and update your billing details.",
        "The account will be locked today unless you confirm your credentials using the link below.",
        "Please reply with your one-time code to verify your identity and unlock access.",
    ],
}

URL_HOSTS = {
    "benign": [
        "docs.example.test", "calendar.example.test", "support.example.test",
        "shop.example.test", "status.example.test",
    ],
    "harmful_url": [
        "paypal-login.example.test", "micros0ft-security.example.test",
        "account-verify.example.test", "secure-wallet.example.test",
        "signin-document.example.test",
    ],
}
URL_PATHS = {
    "benign": [
        "/help/article", "/products/catalog", "/events/schedule",
        "/docs/guide", "/status/overview",
    ],
    "harmful_url": [
        "/login/verify-account", "/secure/restore-access", "/payment/confirm",
        "/identity/validate", "/signin/session",
    ],
}
TOKENS = {
    "team": ["design", "research", "support", "operations", "product"],
    "service": ["Example Books", "Northstar Travel", "Cedar Market", "Sample Cloud", "Papertrail"],
    "month": ["January", "February", "March", "April", "May"],
    "event": ["workshop", "planning session", "community meetup", "review", "training"],
    "weekday": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
    "project": ["website", "mobile app", "onboarding", "accessibility", "release"],
    "prize": ["gift basket", "book bundle", "travel voucher", "coffee set", "store credit"],
    "product": ["headphones", "office supplies", "running shoes", "kitchen tools", "books"],
    "percent": ["10", "15", "20", "25", "30"],
    "account": ["mailbox", "payment account", "online profile", "work account", "subscription"],
    "course": ["cloud security", "first aid", "data analysis", "project management", "networking"],
}


def _format(template: str, index: int) -> str:
    values = {
        key: choices[index % len(choices)]
        for key, choices in TOKENS.items()
    }
    return template.format(**values)


def _email_samples(label: str) -> list[dict[str, Any]]:
    samples = []
    for index, (subject_template, body_template) in enumerate(
        zip(EMAIL_SUBJECTS[label], EMAIL_BODIES[label], strict=True)
    ):
        for variation in range(5):
            sample_index = index + variation
            split = "test" if index == len(EMAIL_SUBJECTS[label]) - 1 else "train"
            sender_domains = {
                "benign": "example.invalid",
                "spam": "promotions.invalid",
                "phishing": "mailbox-security.invalid",
            }
            is_aws_badge = label == "benign" and index == len(EMAIL_SUBJECTS[label]) - 1
            samples.append({
                "kind": "email",
                "label": label,
                "subject": _format(subject_template, sample_index),
                "sender": "admin@credly.com" if is_aws_badge else f"sender{variation}@{sender_domains[label]}",
                "sender_name": "Amazon Web Services Training and Certification via Credly" if is_aws_badge else "",
                "body": _format(body_template, sample_index),
                "url": None,
                "source": "synthetic",
                "is_synthetic": True,
                "dataset_version": DATASET_VERSION,
                "split": split,
            })
    return samples


def _url_samples(label: str) -> list[dict[str, Any]]:
    samples = []
    for host_index, host in enumerate(URL_HOSTS[label]):
        for path_index, path in enumerate(URL_PATHS[label]):
            split = "test" if host_index == len(URL_HOSTS[label]) - 1 else "train"
            samples.append({
                "kind": "url",
                "label": label,
                "subject": None,
                "sender": None,
                "body": None,
                "url": f"https://{host}{path}?ref=sample-{host_index}-{path_index}",
                "source": "synthetic",
                "is_synthetic": True,
                "dataset_version": DATASET_VERSION,
                "split": split,
            })
    return samples


def build_dataset(seed: int = 47) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return deterministic, stratified train/test records with source-family separation."""
    rng = random.Random(seed)
    by_label: dict[str, list[dict[str, Any]]] = {
        "benign": _email_samples("benign") + _url_samples("benign"),
        "spam": _email_samples("spam"),
        "phishing": _email_samples("phishing"),
        "harmful_url": _url_samples("harmful_url"),
    }
    train: list[dict[str, Any]] = []
    test: list[dict[str, Any]] = []
    for label, samples in by_label.items():
        rng.shuffle(samples)
        for index, sample in enumerate(samples):
            split = sample["split"]
            sample["sample_id"] = f"{label}-{index:03d}"
            sample["_id"] = f"{DATASET_VERSION}:{split}:{sample['sample_id']}"
            (test if split == "test" else train).append(sample)
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def write_dataset(output_dir: Path = DEFAULT_OUTPUT) -> tuple[Path, Path]:
    train, test = build_dataset()
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = (output_dir / "train.jsonl", output_dir / "test.jsonl")
    for path, records in zip(paths, (train, test), strict=True):
        path.write_text(
            "".join(json.dumps(record, ensure_ascii=True) + "\n" for record in records),
            encoding="utf-8",
        )
    return paths


if __name__ == "__main__":
    train_path, test_path = write_dataset()
    print(f"Wrote synthetic training data: {train_path}")
    print(f"Wrote synthetic test data: {test_path}")
