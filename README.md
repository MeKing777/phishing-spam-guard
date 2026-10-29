# Phishing & Spam Guard

A phishing and spam checking project with two editions: a public web scanner for checking submitted message text and links, and a local-first Windows toolkit with a Streamlit dashboard, browser tools, Gmail review, and optional local AI.

## What is included

- A public Streamlit web scanner for submitted email text and URLs. It has no Gmail connection and does not store scan history.
- A local Streamlit dashboard for pasted email text, individual URLs, and optional Gmail inbox review.
- A standalone Windows browser with tabs, address/search navigation, page-link highlighting, high-risk navigation prompts, and Gmail/Outlook email scanning.
- Gmail inbox review using the Gmail API. Messages are scored locally and can be moved to Spam or Trash only when you click an action.
- A cross-browser desktop extension named **Alerter** for background link checks and visible Gmail/Outlook message scans.
- Optional local Ollama assessment. It is off unless you request a second opinion.
- Optional `phishing-detection-py` pretrained ML classifier for email and URL phishing checks. It runs only when enabled in Settings and reports separately from the local risk score.
- Transparent checks for suspicious wording, sender/reply-to/Return-Path alignment, reported SPF/DKIM/DMARC results, deceptive link text, brand-like domains, risky attachment names, and URL structure. These are starter checks, not a production reputation service.

## Public web edition

The public website entry point is `public_site/app.py`. It accepts only email text or web addresses that a visitor deliberately submits. It does not connect to Gmail, run Ollama, open links, or keep a scan-history database. The submission is sent to the web server for analysis; the form clears after submission, and only a compact result without the original message, sender, or full URL is kept in that visitor's active session.

To publish it with Streamlit Community Cloud:

1. Push this project to a GitHub repository.
2. Sign in to [Streamlit Community Cloud](https://share.streamlit.io/) with GitHub and create an app from that repository.
3. Select `public_site/app.py` as the app file. Its dependencies are in `public_site/requirements.txt`; no secrets or API keys are required.
4. Set the app to public and share its Streamlit URL.

Visitors send submitted text to the app server. Do not use the public demo for passwords, confidential email, or sensitive personal data. Streamlit Community Cloud currently hosts apps in the United States, and its hosting infrastructure may process standard app traffic. The app itself does not write submitted content to a database or print it to application logs. Review Streamlit's current [deployment guide](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy) and [status and limitations](https://docs.streamlit.io/deploy/streamlit-community-cloud/status) before publishing.

For a local preview of the web edition, run `python -m streamlit run public_site/app.py --server.address=127.0.0.1 --server.port=8502` from the project folder.

## Run the dashboard on Windows

Double-click `run_dashboard.bat` from this project folder. The launcher uses the project's local packages, opens the dashboard in your browser, and leaves a terminal window open so you can see errors. Keep that window open while using the app; press Ctrl+C there to stop it.

If you prefer PowerShell, run the following from the project folder:

```powershell
$env:PYTHONPATH = "$PWD\.runtime_packages;$PWD\.runtime_ml;$PWD\.runtime_packages_extra;$PWD\.runtime_googleauth;$PWD"
$env:HF_HOME = "$PWD\.runtime_ml\hf_cache"
python -m streamlit run app.py --server.address=127.0.0.1 --server.port=8502 --global.developmentMode=false --browser.gatherUsageStats=false
```

## Run Guard Browser on Windows

run_browser.bat opens Guard Browser as its own Windows desktop application. It has browser tabs, an address/search bar, back/forward/reload controls, and a protection switch. It uses the installed Microsoft Edge WebView2 runtime to display regular websites; it does not open Chrome or require an extension.

If the executable has not been built yet, the launcher builds it from the included project. You can also double-click build_browser.bat to create desktop_browser\release\PhishingGuardBrowser.exe directly. Building requires the .NET 9 SDK. Running the published app requires the .NET 9 Desktop Runtime, Microsoft Edge WebView2 Runtime, and Python for local checks. Guard Browser keeps its own local sign-in/profile data under your Windows user account.

With protection enabled, Guard checks page links on this computer, highlights links with warning signs, and asks before opening a high-risk address. When an open Gmail or Outlook message changes, it checks the visible message locally and shows a risk notice. Choose Scan email for the detailed report. The optional Ask local AI button sends that message to Ollama running on this computer only when you click it. The browser does not visit suspicious links or send email contents to a cloud service. It does not automatically delete messages, remove links from websites, or prove that a low-risk result is safe.

The app currently targets Windows PCs. The Streamlit dashboard remains available separately for a responsive phone/PC dashboard; it is not the browser application.
## Set up Gmail access

1. In [Google Cloud Console](https://console.cloud.google.com/), create a project and enable the Gmail API. See Google's [Python quickstart](https://developers.google.com/workspace/gmail/api/quickstart/python) for the official setup flow.
2. Configure the OAuth consent screen. If the app is in testing mode, add the Google account you will use as a test user.
3. Create an OAuth client ID of type **Desktop app** and download the JSON file.
4. Put the file in this project directory as `credentials.json`.
5. In the dashboard, select **Connect / refresh Gmail** and complete Google's authorization flow.

The app requests `https://www.googleapis.com/auth/gmail.modify` because it can move a chosen message to Spam or Trash. It does not send email. The OAuth token is stored locally in `token.json`, which is excluded from Git. Use **Disconnect from this app** to delete that local token, or revoke the app in your Google Account to end its authorization.

## Install the Alerter browser extension

Alerter is an extension for your existing desktop browser; it is not a separate browser application. It is packaged for Chromium browsers and Firefox. Run `browser_extension\build_extensions.py` with Python to create the unpacked folders and ready-to-share ZIP packages.

1. Double-click `start_alerter_checker.bat` and keep its window open. It starts the local Python analyzer on `127.0.0.1`.
2. In Chrome, Edge, Brave, or Opera, open that browser's extensions page, enable **Developer mode**, and choose **Load unpacked**. Select `browser_extension\build\chromium`.
3. In Firefox desktop, open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and select `browser_extension\build\firefox\manifest.json`. Firefox temporary add-ons need to be loaded again after restarting Firefox unless the add-on is signed and installed through Firefox's add-on flow.
4. Review the requested site access and keep Alerter enabled for the sites you want scanned. Open Gmail or Outlook and read a message; Alerter checks the visible message and its links. Click the toolbar icon for a detailed report or to scan again.

Background scanning requires access to pages the extension checks, including webmail content, so the browser will show a site-access permission. Page addresses, links, and visible email text go to the local Python checker on this computer. The extension separately refreshes an active phishing-domain community list from GitHub about every 12 hours; the request contains no visited URL, page, or email content. Hostname comparison happens on-device. Website addresses and links are checked automatically; review/high-risk links are highlighted and prompt before opening, including list matches and suspicious redirect parameters. A server-side redirect to an unlisted destination can only be checked after the destination page loads. On Gmail, Alerter labels each visible inbox preview green (no obvious issue), yellow (review), or red (danger) and continues scanning new previews as you scroll. Outlook automatically checks visible message previews and the currently open message. Only messages visible in the mail app are checked; open a message for a full body and link scan. The popup switch blocks known ad-network requests and pop-up destinations, hides common banner slots, and suppresses known ad-network `window.open` calls. First-party and newly created ads may remain. **Scan visible screen** captures the currently visible tab only after you click it, reads the screenshot with Tesseract installed on this computer, and discards the image when finished. High-risk email or link findings can create a browser notification. Alerter does not delete messages or remove links from websites. It supports desktop Chrome, Edge, Brave, Opera, and Firefox; browser extensions are not available in the same way on every mobile browser, and Safari needs a separately packaged extension.

## Browser-store edition

The self-contained store edition is in `browser_extension/store/`. It performs URL and email checks inside the extension, so each user's message content stays on their device and no local Python service is needed. It includes a locally cached active-phishing-domain list, redirect-parameter checks and click warnings, ad network request blocking, common banner hiding, known ad pop-up blocking, visible Gmail/Outlook preview labels, and automatic open-message checks. The feed update contacts GitHub about twice daily without sending the page URL. Screen OCR remains available only in the local desktop edition. Mail scanning checks only messages currently visible in the page and those exposed as you scroll; it does not fetch the entire mailbox.

Download the browser packages directly from this repository:

- [Chromium (Chrome, Edge, Brave)](browser_extension/store/Alerter-Chromium-Store-2.1.1.zip)
- [Mozilla Firefox](browser_extension/store/Alerter-Firefox-Store-2.1.1.zip)

Run `python browser_extension\store\build_store_extensions.py` to regenerate the store-upload ZIPs in `browser_extension/store/build/`.

## Optional local LLM

Install Ollama and a model locally (`ollama pull llama3.2:3b`), then keep Ollama running. The dashboard defaults to `llama3.2:3b`; enter another installed model name in the sidebar if you prefer. Select **Ask local AI for a second opinion** on a message. Email text is sent to the local Ollama server at `127.0.0.1:11434`, not to a cloud AI API. The app uses Ollama's local [chat API](https://docs.ollama.com/api/chat).

## Optional pretrained phishing model

The app can add an independent phishing-only model opinion using [`phishing-detection-py`](https://pypi.org/project/phishing-detection-py/). It is off by default. Install its optional dependencies in the same Python environment used to run the dashboard:

```powershell
pip install -r requirements-ml.txt
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

Then restart the dashboard and enable **Use the optional ML phishing classifier** in Settings. The first email or URL analysis downloads pretrained Hugging Face model files; later inference runs locally. The model returns a phishing/legitimate label and confidence. Its confidence is not a calibrated probability, it does not detect general spam, and it does not change the explainable local risk score. The package documents email and URL classification in its [official usage guide](https://cmacha2.github.io/phishing-detection-docs/docs/usage/).

## Locally trained email and URL models

The local Python scanner can use compact, on-device classifiers trained from
pinned public datasets. The checked-in training report records 47,573 unique
labeled emails across benign, spam, and phishing classes, plus 11,427 labeled
URLs across legitimate and phishing classes. Email training combines a CC0
spam/ham corpus with a phishing-email corpus declared LGPL-3.0. URL training
uses the CC BY 4.0 Hannousse–Yahiouche academic phishing-URL benchmark. Dataset
citations, revision-pinned download URLs, class counts, grouped holdout metrics,
and limitations are written to `data/threat_intelligence/training_report.json`.
The raw downloads are kept in the ignored `data/training_sources/` directory
and are not committed. The Atlas loader uploads the labeled public corpus only
when you run it with a locally configured `MONGODB_URI`; it never reads inbox
content or browsing history.

To train or reproduce the models locally:

```powershell
python -m pip install -r requirements-training.txt
python -m tools.train_local_models
```

The trainer removes exact normalized duplicate emails and conflicting labels,
keeps duplicate-email groups and URL hostnames within one train/validation/test
split, tunes per-class warning thresholds on validation data, and reports final
metrics on the held-out test split. It writes the local model artifacts under
`models/`. Only model predictions over the validation-set precision threshold
can add a Review warning; the trainer targets at least 98% validation precision
when achievable. The model alone never upgrades a message or URL to High.
Heuristic checks still run, and the browser-store edition remains its own
JavaScript-only detector.

The Atlas loader can store the labeled public corpora in separate email/URL
collections and grouped train/validation/test splits. Loading data does not
train or power live scans; the local classifier uses its local model files.
These corpora are historical and source-biased, not a live threat feed. Email
near-duplicates, source overlap, current campaign drift, and real-world class
prevalence limit the metrics. Email test data is held out by exact normalized
content groups, not by source corpus, so source-specific patterns can inflate
results. Model scores are not calibrated real-world probabilities. The model
is a second signal, not proof that any message or website is safe.

## Detection limits

The Python checks use visible message wording, available mail headers, HTML link text and destinations, attachment filenames, lexical URL traits, and a cached lookup against the public [Phishing.Database active-domain feed](https://github.com/Phishing-Database/Phishing.Database). The browser extension performs the same kind of on-device lookup; neither checker sends scanned URLs to the feed provider. Feeds and heuristics can miss new threats and can occasionally flag a legitimate host. A direct link to an executable file type receives a warning, but Alerter does not download or inspect files and is not antivirus software. Keep your browser's built-in unsafe-site and download protection enabled. Gmail attachments are not downloaded or opened. Authentication results are treated as reported signals; pasted headers may be forged. The app does not cryptographically verify signatures, visit links, or prove that a low-risk message is safe. The optional model is a second opinion, not a validated replacement for local indicators; evaluate it on representative labeled data before relying on it. Keep Spam and Trash actions under the user's control.

## Ideas reviewed

- [phishing-detection-py on PyPI](https://pypi.org/project/phishing-detection-py/) describes pretrained Hugging Face models for email and URL classification. It is integrated as an opt-in, separate classifier; the models and their accuracy have not been independently validated for this app.
- [Phishing Email Analyzer on GitHub](https://github.com/ThestralMoon/Phishing_Email_Analyzer) describes layered, explainable analysis of authentication headers, sender alignment, links, and risky attachment names. The app adds compatible local checks without importing that repository's code.
