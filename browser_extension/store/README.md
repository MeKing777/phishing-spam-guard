# Alerter browser-store edition

This edition is designed for public browser extension stores. It runs the link and email heuristics inside the extension. It does not need Python, a local helper process, a Streamlit login, or a remote analysis API. Page content and scan results stay on the user's device.

The store edition automatically checks the current website address and page links, labels visible Gmail and Outlook previews, scans open messages, and warns on risky destinations. It checks messages currently visible in the page and new messages exposed as you scroll; it cannot certify the entire mailbox. Links with review/high-risk indicators, including phishing-domain matches and suspicious redirect parameters, prompt before opening. The active phishing-domain community list refreshes about every 12 hours and is cached locally. The extension sends no visited URLs, email text, or scan results to the list provider. A match on the current page is reported after navigation; this is not a pre-navigation block for every URL.

The ad switch blocks requests to a broad set of known ad and tracking domains, blocks main-frame navigations to known ad destinations, hides common banner/ad containers, and suppresses `window.open` calls aimed at known ad networks. Ads served from a site's own domain, newly created ad networks, and ad layouts that do not use recognizable markers can remain. This is not a complete EasyList-compatible filter engine. Turn the switch off if a site stops working.

Phishing matches and direct links to executable file types get a high-risk warning before a scanned link opens. Alerter does not download or inspect files and is not antivirus software; keep the browser's built-in unsafe-site and download protection enabled. Community lists and URL heuristics can miss new threats and can occasionally flag legitimate hosts.

Screen-text OCR is not included. The local desktop edition remains in the parent folder and retains optional Tesseract-based screen scanning.

Build the Chromium and Firefox upload archives from the project root with:

```powershell
python browser_extension\store\build_store_extensions.py
```

Ready-to-download packages are also available in this folder: [Chromium](Alerter-Chromium-Store-2.1.1.zip) and [Firefox](Alerter-Firefox-Store-2.1.1.zip). The build command writes fresh ZIP files to `browser_extension/store/build/` and refreshes the versioned packages here. These packages are prepared for store review but are not published to a store. Read [PRIVACY.md](PRIVACY.md) when preparing the listing.
