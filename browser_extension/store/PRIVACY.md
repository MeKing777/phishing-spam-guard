# Alerter browser-store edition privacy notice

The Alerter browser-store edition analyzes web addresses and visible email text on your device. It does not send page contents, email contents, addresses, or scan results to Alerter, the project owner, or a remote analysis service. It does not store a scan history.

The extension reads link destinations on websites so it can identify warning signs and highlight risky links. On Gmail and Outlook, it reads visible message text and sender details to provide an optional scan. These checks run in the extension on your device. A scan result remains in the open extension panel or page notice and is not uploaded.

The extension uses browser notifications to alert you to high-risk findings. It periodically downloads the active phishing-domain text list from the [Phishing.Database project](https://github.com/Phishing-Database/Phishing.Database) at `raw.githubusercontent.com`, about once every 12 hours, and caches the list in browser-local extension storage. This update request does not include the sites you visit, email text, or scan results. The extension compares hostnames on your device. If the list cannot be refreshed, a cached list may be used for up to seven days; after that, only local URL heuristics remain.

The ad switch controls the bundled network rules, recognizable banner hiding, and the known-ad `window.open` guard. It does not subscribe to or download an advertising filter list. Some first-party or newly created ads may remain. Automatic Gmail scanning checks only message previews currently shown in the page and new previews as you scroll; it does not fetch the whole mailbox. Alerter does not visit suspicious links, delete messages, send email, or capture screenshots in the store edition. It does not download or inspect files and is not antivirus software; the browser's built-in unsafe-site and download protections should remain enabled. The store edition does not include screen-text scanning.

You can turn off Alerter's site access or remove the extension at any time in your browser's extension settings.
