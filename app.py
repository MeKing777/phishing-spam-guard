from __future__ import annotations

from datetime import datetime
from html import escape

import streamlit as st

from src.analyzer import analyze_email, analyze_url
from src.gmail_client import connect_gmail, disconnect_gmail, fetch_inbox, move_to_spam, move_to_trash
from src.ml_detector import assess_phishing, phishing_package_installed
from src.ollama_client import explain_with_ollama
from src.trained_detector import models_available


st.set_page_config(
    page_title="Phishing & Spam Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",
)

st.markdown(
    """
<style>
:root {
  --ink: #172033;
  --muted: #667085;
  --line: #e6eaf0;
  --surface: #ffffff;
  --canvas: #f4f7fb;
  --blue: #2563eb;
  --green: #16845b;
  --amber: #b76e00;
  --red: #c43b43;
}
.stApp, [data-testid="stAppViewContainer"] { background: var(--canvas); color: var(--ink); }
[data-testid="stHeader"] { background: rgba(244,247,251,.92); }
section.main > div.block-container { max-width: 1240px; padding: 2rem 2.2rem 3rem; }
[data-testid="stSidebar"] { background: #fff; border-right: 1px solid var(--line); }
[data-testid="stSidebar"] > div:first-child { padding-top: 1.2rem; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: var(--muted); }
[data-testid="stRadio"] label p { font-weight: 550; }
h1, h2, h3 { color: var(--ink) !important; letter-spacing: -.025em; }
h1 { font-size: 2rem !important; }
h2 { font-size: 1.35rem !important; }
p, label, [data-testid="stCaptionContainer"] { color: var(--muted); }
div.stButton > button {
  border-radius: 11px; border: 1px solid #dce3ed; color: var(--ink);
  background: #fff; min-height: 2.7rem; font-weight: 600; transition: .15s ease;
}
div.stButton > button:hover { border-color: #9ab8f7; color: #1749b5; }
div.stButton > button[kind="primary"] { background: var(--blue); border-color: var(--blue); color: #fff; }
div.stButton > button[kind="primary"]:hover { background: #1d4ed8; color: #fff; }
div[data-testid="stTextInput"] input, div[data-testid="stTextArea"] textarea {
  border-radius: 10px; border-color: #dce3ed; background: #fff; color: var(--ink);
}
div[data-testid="stSlider"] [data-baseweb="slider"] { padding-top: .5rem; }
div[data-testid="stExpander"] { border: 1px solid var(--line); border-radius: 12px; background: #fff; }
.brand-lockup { display:flex; align-items:center; gap:11px; padding:4px 8px 20px; }
.brand-mark { width:38px; height:38px; display:grid; place-items:center; background:#eaf1ff; border-radius:12px; font-size:20px; }
.brand-name { color:var(--ink); font-size:15px; font-weight:750; line-height:1.2; }
.brand-caption { color:var(--muted); font-size:11px; margin-top:3px; }
.hero { display:flex; align-items:center; justify-content:space-between; gap:20px; padding:28px 30px; border-radius:20px; color:#fff; background:linear-gradient(115deg,#172b4d 0%,#194a78 64%,#2368a3 100%); box-shadow:0 10px 28px rgba(30,65,110,.14); margin-bottom:22px; }
.hero h1 { color:#fff !important; margin:0 0 8px; font-size:26px !important; }
.hero p { color:#d8e5f6; margin:0; max-width:650px; line-height:1.55; }
.hero-badge { white-space:nowrap; border:1px solid rgba(255,255,255,.25); background:rgba(255,255,255,.1); border-radius:999px; padding:9px 13px; color:#eef5ff; font-size:12px; font-weight:650; }
.metric-card { min-height:142px; padding:18px; background:var(--surface); border:1px solid var(--line); border-radius:15px; box-shadow:0 3px 12px rgba(16,24,40,.035); }
.metric-top { display:flex; align-items:center; justify-content:space-between; color:var(--muted); font-size:12px; font-weight:600; }
.metric-icon { width:34px; height:34px; display:grid; place-items:center; border-radius:10px; background:#f0f4ff; font-size:17px; }
.metric-value { margin-top:12px; color:var(--ink); font-size:27px; font-weight:760; line-height:1.1; }
.metric-note { margin-top:7px; color:var(--muted); font-size:11px; line-height:1.35; }
.section-heading { margin:27px 0 12px; color:var(--ink); font-size:16px; font-weight:720; }
.surface-card { height:100%; padding:18px; border:1px solid var(--line); border-radius:15px; background:#fff; box-shadow:0 3px 12px rgba(16,24,40,.03); }
.surface-title { color:var(--ink); font-size:14px; font-weight:700; margin-bottom:6px; }
.surface-copy { color:var(--muted); font-size:12px; line-height:1.5; }
.status-row { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:12px 0; border-bottom:1px solid #edf0f4; }
.status-row:last-child { border-bottom:0; padding-bottom:0; }
.status-name { color:var(--ink); font-size:13px; font-weight:600; }
.status-copy { color:var(--muted); font-size:11px; margin-top:3px; }
.status-pill { padding:5px 9px; border-radius:999px; white-space:nowrap; font-size:10px; font-weight:700; }
.pill-green { color:#116847; background:#e7f6ef; }
.pill-amber { color:#8b5700; background:#fff3d8; }
.pill-blue { color:#2357b7; background:#eaf1ff; }
.empty-state { padding:22px; border:1px dashed #d5deea; border-radius:13px; background:#fbfcfe; color:var(--muted); font-size:13px; line-height:1.55; }
.risk-high { color:#a72d36; background:#fff0f0; border:1px solid #f7d7d9; padding:12px 14px; border-radius:11px; font-weight:700; }
.risk-review { color:#8b5700; background:#fff7e7; border:1px solid #f2e1b8; padding:12px 14px; border-radius:11px; font-weight:700; }
.risk-low { color:#116847; background:#eaf7f0; border:1px solid #d5eddf; padding:12px 14px; border-radius:11px; font-weight:700; }
.page-subtitle { color:var(--muted); margin-top:-8px; margin-bottom:22px; }
.footer-note { color:#8993a4; font-size:11px; padding-top:18px; }
@media (max-width: 800px) {
  section.main > div.block-container { padding: 1.1rem 1rem 2rem; }
  .hero { align-items:flex-start; flex-direction:column; padding:22px; border-radius:16px; }
  .hero-badge { white-space:normal; }
  .hero h1 { font-size:23px !important; }
  div[data-testid="stHorizontalBlock"] { flex-wrap:wrap; gap:.65rem; }
  div[data-testid="column"] { min-width:calc(50% - .4rem) !important; flex:1 1 calc(50% - .4rem) !important; }
  div.stButton > button { width:100%; min-height:2.9rem; }
}
@media (max-width: 520px) {
  section.main > div.block-container { padding: .8rem .75rem 1.5rem; }
  h1 { font-size:1.55rem !important; }
  div[data-testid="column"] { min-width:100% !important; flex:1 1 100% !important; }
  .metric-card { min-height:unset; }
  .surface-card { padding:15px; }
}
</style>
    """,
    unsafe_allow_html=True,
)


def navigate(page: str) -> None:
    st.session_state.navigation = page


def log_activity(title: str, detail: str) -> None:
    events = st.session_state.setdefault("activity", [])
    events.insert(0, {"time": datetime.now().strftime("%I:%M %p"), "title": title, "detail": detail})
    del events[8:]


def metric_card(icon: str, label: str, value: str | int, note: str) -> None:
    st.markdown(
        f"""<div class="metric-card"><div class="metric-top"><span>{escape(label)}</span><span class="metric-icon">{icon}</span></div>
        <div class="metric-value">{escape(str(value))}</div><div class="metric-note">{escape(note)}</div></div>""",
        unsafe_allow_html=True,
    )


def status_row(name: str, copy: str, status: str, pill_class: str) -> None:
    st.markdown(
        f"""<div class="status-row"><div><div class="status-name">{escape(name)}</div>
        <div class="status-copy">{escape(copy)}</div></div><span class="status-pill {pill_class}">{escape(status)}</span></div>""",
        unsafe_allow_html=True,
    )


def page_header(title: str, subtitle: str) -> None:
    st.markdown(f"# {title}")
    st.markdown(f'<div class="page-subtitle">{escape(subtitle)}</div>', unsafe_allow_html=True)


def show_email_result(result: dict) -> None:
    level = result["risk_level"]
    style = {"High": "risk-high", "Review": "risk-review", "Low": "risk-low"}[level]
    st.markdown(
        f'<div class="{style}">{escape(level)} risk &nbsp;·&nbsp; {result["risk_score"]}/100 &nbsp;·&nbsp; {escape(result["category"])}</div>',
        unsafe_allow_html=True,
    )
    st.markdown("**Why it was flagged**")
    for signal in result["signals"]:
        st.write(f"• {signal}")
    st.caption(result["notice"])
    for item in result["urls"]:
        st.write(f"Link: `{item['host']}` — {item['risk_level']} ({item['risk_score']}/100)")
    if "ml_assessment" in result:
        show_ml_assessment(result["ml_assessment"])
    attachment_names = result.get("attachment_names", [])
    if attachment_names:
        st.markdown("**Attachment names reviewed**")
        for filename in attachment_names:
            st.write(f"📎 `{escape(filename)}`")
        st.caption("Only the names were checked. Attachments were not downloaded or opened.")


def show_ml_assessment(assessment: dict) -> None:
    if assessment.get("status") != "ready":
        st.caption("The optional phishing model was unavailable; the local checks above still ran.")
        return
    confidence = assessment.get("confidence")
    confidence_text = f" · model confidence {confidence:.0%}" if confidence is not None else ""
    st.markdown(f"**Pretrained phishing model:** {escape(assessment['verdict'])}{confidence_text}")
    st.caption("This model checks for phishing only. Its confidence is not a calibrated probability and does not change the local risk score.")


def add_email_ml_assessment(result: dict, subject: str, sender: str, body: str) -> dict:
    if st.session_state.get("phishing_ml_enabled", False):
        model_text = f"Subject: {subject}\nFrom: {sender}\n\n{body}"
        with st.spinner("Checking with the pretrained phishing model…"):
            result["ml_assessment"] = assess_phishing(model_text, model_type="email")
    return result


def explain_locally(subject: str, sender: str, body: str, model: str, key: str) -> None:
    if st.button("Ask local AI for a second opinion", key=key):
        with st.spinner("Checking with your local Ollama model…"):
            try:
                explanation = explain_with_ollama(
                    f"Subject: {subject}\nFrom: {sender}\n\n{body}", model=model
                )
                st.markdown(
                    f"**Local AI view: {escape(explanation.get('risk_level', 'Review'))} · "
                    f"{escape(explanation.get('category', 'Unclear'))}**"
                )
                st.write(explanation.get("explanation", "No explanation returned."))
            except RuntimeError as exc:
                st.error(str(exc))


def render_activity() -> None:
    events = st.session_state.get("activity", [])
    if not events:
        st.markdown(
            '<div class="empty-state"><strong>No scans yet.</strong><br>Run an inbox, email, or link check and its latest result will appear here.</div>',
            unsafe_allow_html=True,
        )
        return
    for event in events[:5]:
        left, right = st.columns([4, 1])
        with left:
            st.markdown(f"**{escape(event['title'])}**")
            st.caption(event["detail"])
        with right:
            st.caption(event["time"])


st.session_state.setdefault("emails_scanned", 0)
st.session_state.setdefault("high_risk_found", 0)
st.session_state.setdefault("links_checked", 0)
st.session_state.setdefault("activity", [])
st.session_state.setdefault("navigation", "Overview")
st.session_state.setdefault("phishing_ml_enabled", True)

with st.sidebar:
    st.markdown(
        '<div class="brand-lockup"><div class="brand-mark">🛡️</div><div><div class="brand-name">Phishing & Spam Guard</div><div class="brand-caption">PERSONAL SECURITY CENTER</div></div></div>',
        unsafe_allow_html=True,
    )
    st.radio(
        "Workspace",
        ["Overview", "Gmail inbox", "Email scanner", "Link scanner", "Settings"],
        key="navigation",
        label_visibility="collapsed",
    )
    st.divider()
    st.markdown("**Protection status**")
    if "gmail_service" in st.session_state:
        st.markdown("🟢 Gmail connected")
    else:
        st.markdown("🟠 Gmail not connected")
    if phishing_package_installed():
        st.markdown("🟢 Optional phishing model installed")
    else:
        st.markdown("⚪ Optional phishing model not installed")
    st.caption("Local checks are ready. Gmail and local AI need setup before use.")
    st.markdown('<div class="footer-note">Your email is analyzed on this computer unless you choose local Ollama.</div>', unsafe_allow_html=True)

ollama_model = st.session_state.get("ollama_model", "llama3.2:3b")
current_page = st.session_state.navigation


if current_page == "Overview":
    st.markdown(
        """<div class="hero"><div><h1>Your security overview</h1>
        <p>Review suspicious emails, spot risky links, and decide what to do from one place.</p></div>
        <div class="hero-badge">● &nbsp; Local protection is ready</div></div>""",
        unsafe_allow_html=True,
    )
    cards = st.columns(4, gap="medium")
    with cards[0]:
        metric_card("📨", "Messages reviewed", st.session_state.emails_scanned, "This app session")
    with cards[1]:
        metric_card("🚨", "High risk found", st.session_state.high_risk_found, "Across completed scans")
    with cards[2]:
        metric_card("🔗", "Links checked", st.session_state.links_checked, "No links are opened")
    with cards[3]:
        metric_card("✉️", "Gmail connection", "On" if "gmail_service" in st.session_state else "Off", "Connect in Settings")

    st.markdown('<div class="section-heading">Quick actions</div>', unsafe_allow_html=True)
    actions = st.columns(3, gap="medium")
    quick_actions = [
        ("📥", "Review Gmail inbox", "Scan recent messages and choose whether to move a flagged email.", "Gmail inbox"),
        ("📝", "Check an email", "Paste a suspicious message to see the indicators found.", "Email scanner"),
        ("🌐", "Check a link", "Inspect a web address without opening it.", "Link scanner"),
    ]
    for column, (icon, title, copy, destination) in zip(actions, quick_actions):
        with column:
            st.markdown(
                f'<div class="surface-card"><div class="surface-title">{icon} &nbsp; {escape(title)}</div><div class="surface-copy">{escape(copy)}</div></div>',
                unsafe_allow_html=True,
            )
            st.button("Open", key=f"quick_{destination}", use_container_width=True, on_click=navigate, args=(destination,))

    lower = st.columns([1.15, 1], gap="large")
    with lower[0]:
        st.markdown('<div class="section-heading">Recent activity</div>', unsafe_allow_html=True)
        with st.container(border=True):
            render_activity()
    with lower[1]:
        st.markdown('<div class="section-heading">Protection status</div>', unsafe_allow_html=True)
        with st.container(border=True):
            status_row("Email and link checks", "Local wording and URL structure analysis", "Ready", "pill-green")
            status_row(
                "Gmail inbox",
                "Connect with Google OAuth to review messages",
                "Connected" if "gmail_service" in st.session_state else "Setup needed",
                "pill-green" if "gmail_service" in st.session_state else "pill-amber",
            )
            status_row("Local AI review", "Optional Ollama second opinion", "Optional", "pill-blue")
            status_row(
                "Pretrained phishing model",
                "Optional email and URL classifier",
                "On" if st.session_state.phishing_ml_enabled else "Off",
                "pill-green" if st.session_state.phishing_ml_enabled else "pill-blue",
            )

elif current_page == "Gmail inbox":
    page_header("Gmail inbox", "Review recent messages, understand the warning signs, and choose any follow-up yourself.")
    if "gmail_service" not in st.session_state:
        with st.container(border=True):
            st.markdown("### Connect your Gmail account")
            st.write("Google OAuth is required before the app can read messages. Your messages are not scanned until you connect and press Scan inbox.")
            st.button("Open Gmail setup", type="primary", on_click=navigate, args=("Settings",))
    else:
        toolbar_left, toolbar_right = st.columns([3, 1])
        with toolbar_left:
            st.markdown("### Recent messages")
            st.caption("Inbox messages from the last 30 days. Each message is analyzed locally.")
        with toolbar_right:
            limit = st.select_slider("Messages", options=[5, 10, 20, 30, 50], value=20)
        if st.button("Scan inbox", type="primary", key="scan_inbox"):
            try:
                messages = fetch_inbox(st.session_state.gmail_service, limit=limit)
                results = []
                for message in messages:
                    result = analyze_email(
                        subject=message["subject"], sender=message["sender"],
                        reply_to=message["reply_to"], body=message["body"],
                        sender_name=message.get("sender_name", ""),
                        return_path=message.get("return_path", ""),
                        authentication_results=message.get("authentication_results", ""),
                        attachment_names=message.get("attachment_names", []),
                        link_pairs=message.get("link_pairs", []),
                    )
                    result = add_email_ml_assessment(
                        result, message["subject"], message["sender"], message["body"]
                    )
                    results.append({"message": message, "result": result})
                st.session_state.inbox_results = results
                st.session_state.emails_scanned += len(results)
                high_count = sum(item["result"]["risk_level"] == "High" for item in results)
                st.session_state.high_risk_found += high_count
                st.session_state.inbox_scan_done = True
                log_activity("Gmail inbox scan", f"Reviewed {len(results)} messages · {high_count} high risk")
            except Exception as exc:
                st.error(f"Could not read Gmail: {exc}")

        if "inbox_results" in st.session_state and st.session_state.inbox_results:
            st.caption(f"{len(st.session_state.inbox_results)} messages reviewed")
            for item in st.session_state.inbox_results:
                message, result = item["message"], item["result"]
                label = f"{result['risk_level']} · {message['subject']} — {message['sender']}"
                with st.expander(label, expanded=result["risk_level"] != "Low"):
                    st.caption(message["date"])
                    st.write(message["snippet"] or message["body"][:500] or "No readable message text was available.")
                    show_email_result(result)
                    explain_locally(message["subject"], message["sender"], message["body"], ollama_model, f"ollama_{message['id']}")
                    spam_col, trash_col = st.columns(2)
                    with spam_col:
                        if st.button("Move to Spam", key=f"spam_{message['id']}"):
                            try:
                                move_to_spam(st.session_state.gmail_service, message["id"])
                            except Exception as exc:
                                st.error(f"Could not move this message to Spam: {exc}")
                            else:
                                st.session_state.inbox_results = [row for row in st.session_state.inbox_results if row["message"]["id"] != message["id"]]
                                log_activity("Message moved to Spam", "You chose to move a message from the inbox.")
                                st.rerun()
                    with trash_col:
                        if st.button("Move to Trash", key=f"trash_{message['id']}"):
                            try:
                                move_to_trash(st.session_state.gmail_service, message["id"])
                            except Exception as exc:
                                st.error(f"Could not move this message to Trash: {exc}")
                            else:
                                st.session_state.inbox_results = [row for row in st.session_state.inbox_results if row["message"]["id"] != message["id"]]
                                log_activity("Message moved to Trash", "You chose to move a message from the inbox.")
                                st.rerun()
        elif st.session_state.get("inbox_scan_done"):
            st.markdown('<div class="empty-state">No messages matched the current inbox scan.</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="empty-state">Select <strong>Scan inbox</strong> to review your recent messages.</div>', unsafe_allow_html=True)

elif current_page == "Email scanner":
    page_header("Email scanner", "Check suspicious email or message text and see which indicators influenced the result.")
    with st.container(border=True):
        sender = st.text_input("Sender address (optional)", key="email_sender")
        sender_name = st.text_input("Sender display name (optional)", key="email_sender_name")
        reply_to = st.text_input("Reply-to address (optional)", key="email_reply_to")
        subject = st.text_input("Subject (optional)", key="email_subject")
        email_text = st.text_area("Email or message text", height=220, key="email_body", placeholder="Paste the message you want to review…")
        with st.expander("More email headers (optional)"):
            return_path = st.text_input("Return-Path", key="email_return_path")
            authentication_results = st.text_area(
                "Authentication-Results",
                key="email_authentication_results",
                height=90,
                help="Use the receiving mail provider's header when available. Text pasted here can be spoofed, so treat it as one signal.",
            )
        if st.button("Analyze email", type="primary", key="analyze_email"):
            if not email_text.strip() and not subject.strip():
                st.warning("Paste some email text or enter a subject first.")
                st.session_state.pop("pasted_analysis", None)
            else:
                result = analyze_email(
                    subject=subject,
                    sender=sender,
                    sender_name=sender_name,
                    reply_to=reply_to,
                    return_path=return_path,
                    authentication_results=authentication_results,
                    body=email_text,
                )
                result = add_email_ml_assessment(result, subject, sender, email_text)
                st.session_state.pasted_analysis = {
                    "inputs": (sender, sender_name, reply_to, return_path, authentication_results, subject, email_text),
                    "result": result,
                }
                st.session_state.emails_scanned += 1
                if result["risk_level"] == "High":
                    st.session_state.high_risk_found += 1
                log_activity("Email text check", f"Result: {result['risk_level']} risk · {result['risk_score']}/100")

    saved_analysis = st.session_state.get("pasted_analysis")
    if saved_analysis and saved_analysis["inputs"] == (
        sender, sender_name, reply_to, return_path, authentication_results, subject, email_text
    ):
        with st.container(border=True):
            st.markdown("### Analysis result")
            show_email_result(saved_analysis["result"])
            explain_locally(subject, sender, email_text, ollama_model, "ollama_pasted")

elif current_page == "Link scanner":
    page_header("Link scanner", "Inspect a web address without opening it. Its hostname is compared locally with a cached community phishing list; the list provider does not receive the address.")
    with st.container(border=True):
        url = st.text_input("Web address", key="link_input", placeholder="https://example.com/login")
        if st.button("Analyze link", type="primary", key="analyze_link"):
            if not url.strip():
                st.warning("Enter a web address first.")
                st.session_state.pop("link_analysis", None)
            else:
                result = analyze_url(url.strip())
                if st.session_state.get("phishing_ml_enabled", False):
                    with st.spinner("Checking with the pretrained link model…"):
                        result["ml_assessment"] = assess_phishing(url.strip(), model_type="url")
                st.session_state.link_analysis = {"url": url, "result": result}
                st.session_state.links_checked += 1
                log_activity("Link check", f"Result: {result['risk_level']} risk · {result['risk_score']}/100")

    saved_link = st.session_state.get("link_analysis")
    if saved_link and saved_link["url"] == url:
        result = saved_link["result"]
        style = {"High": "risk-high", "Review": "risk-review", "Low": "risk-low"}[result["risk_level"]]
        with st.container(border=True):
            st.markdown("### Analysis result")
            st.markdown(
                f'<div class="{style}">{escape(result["risk_level"])} risk &nbsp;·&nbsp; {result["risk_score"]}/100</div>',
                unsafe_allow_html=True,
            )
            st.markdown(f"**Domain:** `{result['host']}`")
            for signal in result["signals"]:
                st.write(f"• {signal}")
            if "ml_assessment" in result:
                show_ml_assessment(result["ml_assessment"])
            st.caption("A Low score is not proof that a website is safe.")

elif current_page == "Settings":
    page_header("Settings & connections", "Connect services and configure optional local analysis.")
    left, right = st.columns(2, gap="large")
    with left:
        with st.container(border=True):
            st.markdown("### Gmail connection")
            if "gmail_service" in st.session_state:
                st.success("Gmail is connected for this session.")
                if st.button("Disconnect Gmail", key="disconnect_gmail"):
                    disconnect_gmail()
                    st.session_state.pop("gmail_service", None)
                    st.session_state.pop("inbox_results", None)
                    st.rerun()
            else:
                st.write("Connect using Google OAuth to scan your recent inbox. The app requests access so it can read messages and move a message to Spam or Trash only after you choose an action.")
                if st.button("Connect Gmail", type="primary", key="connect_gmail"):
                    try:
                        st.session_state.gmail_service = connect_gmail()
                        st.success("Gmail connected for this session.")
                    except Exception as exc:
                        st.error(str(exc))
            st.markdown("**One-time setup**")
            st.markdown("Enable the Gmail API in Google Cloud, create a **Desktop app** OAuth client, and save its JSON file here as `credentials.json`. Then select Connect Gmail.")

    with right:
        trained_models = models_available()
        with st.container(border=True):
            st.markdown("### Local trained classifiers")
            ready_models = [name for name, available in trained_models.items() if available]
            if ready_models:
                st.success(f"Active locally: {', '.join(ready_models)}")
            else:
                st.info("Not trained on this computer yet. Run `python -m tools.train_local_models`.")
            st.caption(
                "Email and URL predictions run locally and can add a Review warning "
                "when the validation-tuned threshold is met. Heuristic checks still run."
            )
        with st.container(border=True):
            st.markdown("### Pretrained phishing model")
            st.checkbox(
                "Use the optional ML phishing classifier",
                key="phishing_ml_enabled",
                help="Adds an independent phishing model opinion to email and link scans. It does not change the transparent local risk score.",
            )
            st.caption("The model detects phishing only, not general spam. Its first use downloads model files; subsequent inference runs on this computer.")
            if phishing_package_installed():
                st.success("The Python package is installed. If its model backend is missing, follow the install commands below and restart the dashboard.")
            else:
                st.info("Optional model package is not installed. Local checks are available without it.")
            st.code(
                "pip install -r requirements-ml.txt\npip install torch --index-url https://download.pytorch.org/whl/cpu",
                language="powershell",
            )
            st.caption("Model files download from Hugging Face on first use. Keep this option off if you do not want to download them.")
        with st.container(border=True):
            st.markdown("### Local AI second opinion")
            model = st.text_input("Ollama model", value=ollama_model, key="settings_ollama_model")
            st.session_state.ollama_model = model.strip() or "llama3.2:3b"
            st.caption("Optional. Install Ollama and the selected model on this computer. Email text is sent to your local Ollama service only when you request a second opinion.")
        with st.container(border=True):
            st.markdown("### Browser link checker")
            st.write("The optional Chrome extension checks only the active tab's address after you click it. It does not read page content.")
            st.code("uvicorn api:app --host 127.0.0.1 --port 8765", language="powershell")
            st.caption("Load the `browser_extension` folder from chrome://extensions with Developer mode enabled.")

st.markdown('<div class="footer-note">Local risk indicators are guidance, not proof that an email or website is safe.</div>', unsafe_allow_html=True)
