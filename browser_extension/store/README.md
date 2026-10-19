# Alerter browser-store edition

This edition is designed for public browser extension stores. It runs the link and email heuristics inside the extension. It does not need Python, a local helper process, a Streamlit login, or a remote analysis API. Page content and scan results stay on the user's device.

The store edition includes page-link checks, visible Gmail previews, and open Gmail or Outlook message scans. Screen-text OCR is not included. The local desktop edition remains in the parent folder and retains optional Tesseract-based screen scanning.

Build the Chromium and Firefox upload archives from the project root with:

```powershell
python browser_extension\store\build_store_extensions.py
```

The resulting ZIP files are written to `browser_extension/store/build/`. They are prepared for store review but are not published to a store. Read [PRIVACY.md](PRIVACY.md) when preparing the listing.
