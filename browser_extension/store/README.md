# Alerter browser-store edition

This edition is designed for public browser extension stores. It runs the link and email heuristics inside the extension. It does not need Python, a local helper process, a Streamlit login, or a remote analysis API. Page content and scan results stay on the user's device.

The store edition automatically checks the current website address and page links, labels visible Gmail and Outlook previews, scans open messages, and warns on risky destinations. It checks messages currently visible in the page and new messages exposed as you scroll; it cannot certify the entire mailbox. Links with review/high-risk indicators, including suspicious destinations embedded in common redirect parameters, prompt before opening. Server-side redirects to an unseen destination are checked after navigation, not blocked in advance. A built-in, on-device ruleset blocks requests to a limited set of common ad and tracking domains; use the popup switch to disable it if a site breaks. This is a starter ruleset, not a full filter-list or cosmetic ad blocker.

Screen-text OCR is not included. The local desktop edition remains in the parent folder and retains optional Tesseract-based screen scanning.

Build the Chromium and Firefox upload archives from the project root with:

```powershell
python browser_extension\store\build_store_extensions.py
```

The resulting ZIP files are written to `browser_extension/store/build/`. They are prepared for store review but are not published to a store. Read [PRIVACY.md](PRIVACY.md) when preparing the listing.
