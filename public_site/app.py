"""Public web edition of Phishing & Spam Guard.

This edition accepts only text and URLs that a visitor submits deliberately.
It does not connect to Gmail, follow links, or persist scan history.
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzer import analyze_email, analyze_url  # noqa: E402


st.set_page_config(
    page_title="Phishing & Spam Guard",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .block-container { max-width: 900px; padding-top: 2.3rem; padding-bottom: 3rem; }
    .hero { padding: 26px 28px; border-radius: 18px; color: #fff;
        background: linear-gradient(115deg,#172b4d 0%,#194a78 64%,#2368a3 100%);
        margin-bottom: 18px; }
    .hero h1 { color: #fff !important; margin: 0 0 8px; font-size: 28px !important; }
    .hero p { color: #d8e5f6; margin: 0; line-height: 1.55; }
    .risk { padding: 13px 15px; border-radius: 11px; font-weight: 700; margin: 12px 0; }
    .risk-high { color: #8e1d27; background: #fff0f0; border: 1px solid #f2c7ca; }
    .risk-review { color: #765000; background: #fff7e7; border: 1px solid #ecd9a7; }
    .risk-low { color: #116847; background: #eaf7f0; border: 1px solid #cce7d8; }
    .footnote { color: #687386; font-size: 12px; line-height: 1.55; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """<div class="hero"><h1>Phishing &amp; Spam Guard</h1>
    <p>Review suspicious message wording and web addresses before you act.</p></div>""",
    unsafe_allow_html=True,
)

st.warning(
    "Online processing: anything you submit is sent to the server running this website for analysis. "
    "Avoid passwords, sensitive personal details, and confidential messages. The app keeps no scan "
    "history in a database; your submission is processed in your active web session, and hosting "
    "infrastructure may process standard app traffic."
)

st.caption(
    "Checks run on this app's server. Course-badge notices are assessed with sender context; generic congratulations or reward words alone are not treated as spam. Web addresses are compared with a cached public phishing-domain list, but links are never opened. The list provider receives no submitted address or message text."
)
st.checkbox(
    "I understand that text or links I submit are sent to this website's server for analysis.",
    key="submission_consent",
)


def compact_email_result(result: dict) -> dict:
    """Keep only findings in session state, not the submitted message or sender data."""
    return {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "category": result["category"],
        "signals": result["signals"],
        "urls": [
            {
                "host": item["host"],
                "risk_score": item["risk_score"],
                "risk_level": item["risk_level"],
                "signals": item["signals"],
            }
            for item in result["urls"]
        ],
        "notice": result["notice"],
    }


def show_email_result(result: dict) -> None:
    level = result["risk_level"]
    style = {"High": "risk-high", "Review": "risk-review", "Low": "risk-low"}[level]
    st.markdown(
        f'<div class="risk {style}">{escape(level)} risk · {result["risk_score"]}/100 · '
        f'{escape(result["category"])}</div>',
        unsafe_allow_html=True,
    )
    st.markdown("**Signals found**")
    for signal in result["signals"]:
        st.write(f"• {signal}")
    for item in result["urls"]:
        st.write(f"Link host: `{item['host']}` — {item['risk_level']} ({item['risk_score']}/100)")
    st.caption(result["notice"])


def show_url_result(result: dict) -> None:
    level = result["risk_level"]
    style = {"High": "risk-high", "Review": "risk-review", "Low": "risk-low"}[level]
    st.markdown(
        f'<div class="risk {style}">{escape(level)} risk · {result["risk_score"]}/100</div>',
        unsafe_allow_html=True,
    )
    st.markdown(f"**Domain:** `{result['host']}`")
    st.markdown("**Signals found**")
    for signal in result["signals"]:
        st.write(f"• {signal}")
    st.caption("A Low score is not proof that a website is safe.")


scan_type = st.radio("Choose a check", ["Email text", "Web address"], horizontal=True)

if scan_type == "Email text":
    st.subheader("Check a suspicious email")
    with st.form("email_scan", clear_on_submit=True):
        subject = st.text_input("Subject (optional)", max_chars=500)
        sender = st.text_input("Sender address (optional)", max_chars=320)
        sender_name = st.text_input("Sender display name (optional)", max_chars=160)
        reply_to = st.text_input("Reply-to address (optional)", max_chars=320)
        body = st.text_area(
            "Message text",
            max_chars=20_000,
            height=220,
            placeholder="Paste only the parts you want checked…",
        )
        submitted = st.form_submit_button(
            "Analyze email",
            type="primary",
            use_container_width=True,
            disabled=not st.session_state.submission_consent,
        )

    if submitted:
        st.session_state.pop("email_result", None)
        if not body.strip() and not subject.strip():
            st.warning("Enter a subject or message text first.")
        else:
            try:
                result = analyze_email(
                    subject=subject,
                    sender=sender,
                    sender_name=sender_name,
                    reply_to=reply_to,
                    body=body,
                )
                st.session_state.email_result = compact_email_result(result)
            except Exception:
                st.error("The message could not be analyzed. Check the length and try again.")

    if "email_result" in st.session_state:
        with st.container(border=True):
            st.subheader("Analysis result")
            show_email_result(st.session_state.email_result)

else:
    st.subheader("Check a web address")
    with st.form("url_scan", clear_on_submit=True):
        url = st.text_input(
            "Web address",
            max_chars=4_096,
            placeholder="https://example.com/login",
        )
        submitted = st.form_submit_button(
            "Analyze link",
            type="primary",
            use_container_width=True,
            disabled=not st.session_state.submission_consent,
        )

    if submitted:
        st.session_state.pop("url_result", None)
        if not url.strip():
            st.warning("Enter a web address first.")
        else:
            try:
                result = analyze_url(url.strip())
                st.session_state.url_result = {
                    key: result[key]
                    for key in ("host", "risk_score", "risk_level", "signals")
                }
            except Exception:
                st.error("The address could not be analyzed. Check it and try again.")

    if "url_result" in st.session_state:
        with st.container(border=True):
            st.subheader("Analysis result")
            show_url_result(st.session_state.url_result)

with st.expander("How this checker works and its limits"):
    st.markdown(
        """
        - Looks for common urgency, credential, payment, sender-alignment, and URL-structure signals.
        - Treats prize claims and payment requests as stronger evidence than words such as “Congratulations” or “Unsubscribe” by themselves.
        - Does not open links, download attachments, or verify identities. Address checks compare hostnames locally against a cached public phishing-domain list; that provider does not receive the submitted address.
        - A low-risk result does not prove a message or website is safe. Treat this as a first-pass aid.
        - No Gmail inbox is connected, and no email is sent, moved, or deleted.
        """
    )

st.markdown(
    '<div class="footnote">Phishing &amp; Spam Guard · Public web edition · Scan results are guidance, not a safety guarantee.</div>',
    unsafe_allow_html=True,
)
