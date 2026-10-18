(() => {
  if (window.__alerterLoaded) return;
  window.__alerterLoaded = true;

  const ratings = new Map();
  const seen = new Set();
  let checking = false;
  let linkTimer;
  let emailTimer;
  let lastEmailFingerprint = "";
  let notifiedHigh = false;
  let scanningInbox = false;
  let lastInboxScanAttempt = 0;
  let linkBadge;
  let emailBadge;
  const inboxFingerprints = new Map();
  const notifiedInboxEmails = new Set();

  function makeBadge(kind) {
    const host = document.createElement("div");
    host.style.cssText = kind === "email"
      ? "all:initial;position:fixed;z-index:2147483647;right:12px;bottom:12px"
      : "all:initial;position:fixed;z-index:2147483647;top:12px;right:12px";
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      *{box-sizing:border-box;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
      .card{width:min(360px,calc(100vw - 24px));padding:13px 14px;border:1px solid #ead2a0;border-radius:13px;background:#fff9ec;color:#563d11;box-shadow:0 10px 38px #15223830}
      .card.high{border-color:#f0bec2;background:#fff1f1;color:#772c32}
      .card.safe{border-color:#c9e5d5;background:#eff9f3;color:#235d40}
      .row{display:flex;align-items:flex-start;gap:10px}.copy{min-width:0;flex:1}.title{font-size:13px;font-weight:750;line-height:1.35}.detail{margin-top:4px;font-size:11px;line-height:1.5;overflow-wrap:anywhere}
      .actions{display:flex;gap:8px;margin-top:10px}.actions button{border:1px solid #d3dbea;border-radius:8px;padding:7px 10px;background:white;color:#263750;font-size:11px;font-weight:700;cursor:pointer}.actions .primary{border-color:#a33139;background:#a33139;color:white}.dismiss{border:0;background:transparent;color:inherit;font-size:18px;line-height:1;cursor:pointer}
      ul{margin:7px 0 0;padding-left:17px;font-size:11px;line-height:1.45}
    `;
    const card = document.createElement("section");
    card.className = "card";
    card.setAttribute("role", "status");
    shadow.append(style, card);
    document.documentElement.append(host);
    if (kind === "email") emailBadge = { host, card };
    else linkBadge = { host, card };
    return { host, card };
  }

  function removeBadge(kind) {
    const badge = kind === "email" ? emailBadge : linkBadge;
    badge?.host.remove();
    if (kind === "email") emailBadge = null;
    else linkBadge = null;
  }

  function showNotice(kind, title, detail, signals = [], actions = [], tone = "") {
    const { card } = kind === "email" ? (emailBadge || makeBadge("email")) : (linkBadge || makeBadge("link"));
    card.className = `card ${tone || (kind === "email" ? "email" : "high")}`;
    card.replaceChildren();
    const row = document.createElement("div");
    row.className = "row";
    const copy = document.createElement("div");
    copy.className = "copy";
    const heading = document.createElement("div");
    heading.className = "title";
    heading.textContent = title;
    copy.append(heading);
    if (detail) {
      const body = document.createElement("div");
      body.className = "detail";
      body.textContent = detail;
      copy.append(body);
    }
    if (signals.length) {
      const list = document.createElement("ul");
      for (const signal of signals.slice(0, 4)) {
        const item = document.createElement("li");
        item.textContent = signal;
        list.append(item);
      }
      copy.append(list);
    }
    row.append(copy);
    const close = document.createElement("button");
    close.className = "dismiss";
    close.type = "button";
    close.setAttribute("aria-label", "Dismiss security notice");
    close.textContent = "×";
    close.addEventListener("click", () => removeBadge(kind));
    row.append(close);
    card.append(row);
    if (actions.length) {
      const bar = document.createElement("div");
      bar.className = "actions";
      for (const action of actions) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = action.primary ? "primary" : "";
        button.textContent = action.label;
        button.addEventListener("click", action.run);
        bar.append(button);
      }
      card.append(bar);
    }
    return card;
  }

  function notifyThreat(title, message) {
    try {
      chrome.runtime.sendMessage({ type: "notify-threat", title, message }, () => {
        void chrome.runtime.lastError;
      });
    } catch {}
  }

  function queuePageLinks(root = document) {
    const anchors = [];
    if (root instanceof HTMLAnchorElement && root.hasAttribute("href")) anchors.push(root);
    if (root.querySelectorAll) anchors.push(...root.querySelectorAll("a[href]"));
    for (const anchor of anchors) {
      try {
        const href = new URL(anchor.href, location.href);
        if (!/^https?:$/.test(href.protocol) || seen.has(href.href)) continue;
        seen.add(href.href);
      } catch {}
    }
    clearTimeout(linkTimer);
    linkTimer = setTimeout(scanLinks, 350);
  }

  async function scanLinks() {
    if (checking) return;
    const links = [...document.querySelectorAll("a[href]")].filter((a) => {
      try { return seen.has(new URL(a.href, location.href).href) && !ratings.has(a.href); }
      catch { return false; }
    });
    const unique = [...new Set(links.map((a) => a.href))].filter((href) => !ratings.has(href));
    if (!unique.length) return;
    checking = true;
    try {
      for (let start = 0; start < unique.length; start += 80) {
        const response = await chrome.runtime.sendMessage({ type: "analyze-links", urls: unique.slice(start, start + 80) });
        if (!response?.ok) throw new Error(response?.error || "The local checker is unavailable");
        for (const result of response.result || []) ratings.set(result.url, result);
      }
      for (const anchor of document.querySelectorAll("a[href]")) {
        if (anchor.dataset.guardUrl !== anchor.href) {
          delete anchor.dataset.guardRisk;
          if (/^(?:Alerter|Guard):/.test(anchor.title || "")) anchor.removeAttribute("title");
          anchor.dataset.guardUrl = anchor.href;
        }
        const result = ratings.get(anchor.href);
        if (!result) continue;
        if (result.risk_level === "High" || result.risk_level === "Review") {
          anchor.dataset.guardRisk = result.risk_level.toLowerCase();
          anchor.title = `Alerter: ${result.risk_level} risk (${result.risk_score}/100). ${(result.signals || []).slice(0, 2).join("; ")}`;
        }
      }
      const highResults = [...new Map(unique.map((url) => ratings.get(url)).filter((item) => item?.risk_level === "High").map((item) => [item.url, item])).values()];
      if (highResults.length && !notifiedHigh) {
        notifiedHigh = true;
        showNotice("link", "Suspicious link highlighted", `${highResults.length} high-risk link destination${highResults.length === 1 ? " was" : "s were"} found. Alerter will warn before opening them.`, highResults.slice(0, 3).map((item) => `${item.host} · ${item.risk_score}/100`));
        notifyThreat("Alerter found a risky link", `A high-risk link was found on ${location.hostname}. Review the warning before opening it.`);
      }
      if (!document.getElementById("__phishingSpamGuardStyles")) {
        const style = document.createElement("style");
        style.id = "__phishingSpamGuardStyles";
        style.textContent = 'a[data-guard-risk="high"]{outline:2px solid #c43b43!important;outline-offset:2px!important;background:#fff0f0!important;border-radius:3px!important}a[data-guard-risk="review"]{outline:2px solid #b76e00!important;outline-offset:2px!important;background:#fff7e7!important;border-radius:3px!important}';
        (document.head || document.documentElement).append(style);
      }
    } catch (error) {
      if (!window.__guardServiceNoticeShown) {
        window.__guardServiceNoticeShown = true;
        showNotice("link", "Alerter checker is offline", "Start start_alerter_checker.bat from the project folder to restore local checks.");
      }
      console.warn("Alerter:", error.message);
    } finally { checking = false; }
  }

  function highRiskClick(event) {
    const anchor = event.composedPath().find((node) => node instanceof HTMLAnchorElement);
    if (!anchor) return;
    const result = ratings.get(anchor.href);
    if (result?.risk_level !== "High") return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const card = showNotice("link", "This link looks risky", `${result.host} · ${result.risk_score}/100`, result.signals || [], [
      { label: "Stay here", run: () => removeBadge("link") },
      { label: "Open anyway", primary: true, run: () => { const href = anchor.href; const newTab = anchor.target === "_blank"; removeBadge("link"); if (newTab) window.open(href, "_blank", "noopener"); else location.assign(href); } },
    ]);
    card.setAttribute("role", "alertdialog");
  }

  function extractOpenEmail() {
    const host = location.hostname.toLowerCase();
    const gmail = host === "mail.google.com";
    const outlook = ["outlook.live.com", "outlook.office.com", "outlook.office365.com"].includes(host);
    if (!gmail && !outlook) return { supported: false };
    const visible = (element) => {
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    };
    const candidates = (gmail
      ? [...document.querySelectorAll(".a3s")]
      : [...document.querySelectorAll('[aria-label*="Message body"],[data-testid*="messageBody"],.ReadingPaneContents,[role="document"],article')])
      .filter(visible).filter((element) => { const text = (element.innerText || "").trim(); return text.length >= 20 && text.length <= 30000; });
    const node = candidates.at(-1);
    const selected = (window.getSelection?.().toString() || "").trim();
    const body = (selected || node?.innerText || "").trim().slice(0, 20000);
    if (!body) return { supported: true, found: false };
    const senderNodes = gmail ? [...document.querySelectorAll("span.gD[email]")] : [...document.querySelectorAll('[data-testid*="sender"]')];
    const senderNode = senderNodes.filter(visible).at(-1);
    const scope = node || document;
    return {
      supported: true, found: true,
      subject: (document.querySelector("h2.hP")?.innerText || document.querySelector('[role="heading"][aria-level="2"]')?.innerText || "").trim().slice(0, 250),
      sender: senderNode?.getAttribute("email") || senderNode?.getAttribute("title") || "",
      sender_name: (senderNode?.innerText || "").trim().slice(0, 120),
      body,
      link_pairs: [...(scope.querySelectorAll?.("a[href]") || [])].slice(0, 60).map((a) => ({ href: a.href, text: (a.innerText || a.getAttribute("aria-label") || "").trim().slice(0, 160) })),
    };
  }

  function extractVisibleGmailPreviews() {
    if (location.hostname.toLowerCase() !== "mail.google.com") return [];
    const isVisible = (element) => {
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    };
    return [...document.querySelectorAll("tr.zA")]
      .filter(isVisible)
      .slice(0, 12)
      .map((row, index) => {
        const senderNode = row.querySelector("[email]");
        const subjectNode = row.querySelector(".bog") || row.querySelector(".y6 span");
        const snippetNode = row.querySelector(".y2");
        const sender = (senderNode?.getAttribute("email") || "").trim().slice(0, 320);
        const senderName = (row.querySelector(".yW")?.innerText || senderNode?.innerText || "").trim().slice(0, 120);
        const subject = (subjectNode?.innerText || "").trim().slice(0, 250);
        const body = (snippetNode?.innerText || "").trim().slice(0, 700);
        if (!sender && !subject && !body) return null;
        const previewId = row.getAttribute("data-legacy-thread-id") || row.querySelector('a[href*="#"]')?.getAttribute("href") || `visible-${index}`;
        row.dataset.alerterPreviewId = previewId;
        return {
          subject,
          sender,
          sender_name: senderName,
          body,
          link_pairs: [],
          preview_only: true,
          preview_id: previewId,
        };
      })
      .filter(Boolean);
  }

  function highlightInboxPreview(email, result) {
    const row = [...document.querySelectorAll("tr.zA")]
      .find((item) => item.dataset.alerterPreviewId === email.preview_id);
    if (!row) return;
    const level = String(result.risk_level || "").toLowerCase();
    if (level === "high" || level === "review") {
      row.dataset.alerterRisk = level;
      row.title = `Alerter: ${result.risk_level} risk (${result.risk_score}/100). ${(result.signals || []).slice(0, 2).join("; ")}`;
    } else {
      delete row.dataset.alerterRisk;
      if ((row.title || "").startsWith("Alerter:")) row.removeAttribute("title");
    }
    if (!document.getElementById("__alerterInboxStyles")) {
      const style = document.createElement("style");
      style.id = "__alerterInboxStyles";
      style.textContent = 'tr[data-alerter-risk="high"]{box-shadow:inset 4px 0 #c43b43!important;background:#fff0f0!important}tr[data-alerter-risk="review"]{box-shadow:inset 4px 0 #b76e00!important;background:#fff8e9!important}';
      (document.head || document.documentElement).append(style);
    }
  }

  async function scanVisibleGmailInbox() {
    if (scanningInbox) return;
    const previews = extractVisibleGmailPreviews();
    if (!previews.length || Date.now() - lastInboxScanAttempt < 4500) return;
    lastInboxScanAttempt = Date.now();
    const pending = previews.filter((email) => {
      const fingerprint = `${email.subject}|${email.sender}|${email.body}`;
      return inboxFingerprints.get(email.preview_id) !== fingerprint;
    });
    if (!pending.length) return;
    scanningInbox = true;
    try {
      const checked = await Promise.all(pending.map(async (email) => {
        const response = await chrome.runtime.sendMessage({ type: "analyze-email", email });
        if (!response?.ok) throw new Error(response?.error || "The local checker is unavailable");
        const fingerprint = `${email.subject}|${email.sender}|${email.body}`;
        inboxFingerprints.set(email.preview_id, fingerprint);
        highlightInboxPreview(email, response.result);
        return { email, result: response.result };
      }));
      const newHighRisk = checked.filter(({ email, result }) =>
        result.risk_level === "High" && !notifiedInboxEmails.has(email.preview_id));
      for (const { email } of newHighRisk) notifiedInboxEmails.add(email.preview_id);
      if (newHighRisk.length) {
        showNotice("email", "Alerter found a risky email preview", `${newHighRisk.length} visible Gmail preview${newHighRisk.length === 1 ? " has" : "s have"} high-risk warning signs. Open a message for the full scan.`, newHighRisk.slice(0, 3).map(({ email, result }) => `${email.sender_name || email.sender || "Sender"} · ${result.risk_score}/100`), [], "high");
        notifyThreat("Alerter flagged a Gmail preview", "A visible email preview shows phishing or spam warning signs. Open the message and scan it for a full report.");
      }
    } catch (error) {
      console.warn("Alerter Gmail preview scan skipped:", error.message);
    } finally {
      scanningInbox = false;
    }
  }

  async function scanOpenEmail(showFailure = false) {
    const email = extractOpenEmail();
    if (!email.supported || !email.found) {
      if (showFailure) showNotice("email", "Open a message first", "Open one email in Gmail or Outlook, then scan it again.");
      return { ok: false, error: "Open a message in Gmail or Outlook first." };
    }
    const fingerprint = `${location.pathname}|${email.subject}|${email.sender}|${email.body.slice(0, 700)}`;
    if (!showFailure && fingerprint === lastEmailFingerprint) return { ok: true, skipped: true };
    lastEmailFingerprint = fingerprint;
    const response = await chrome.runtime.sendMessage({ type: "analyze-email", email });
    if (!response?.ok) {
      if (showFailure) showNotice("email", "Email check is offline", response?.error || "Start Alerter's local checker and try again.");
      return { ok: false, error: response?.error || "Local email check failed" };
    }
    const result = response.result;
    const summary = `${result.risk_level} risk · ${result.risk_score}/100 · ${result.category}`;
    const tone = result.risk_level === "High" ? "high" : result.risk_level === "Low" ? "safe" : "email";
    showNotice("email", "Email scan complete", summary, result.signals || [], [], tone);
    if (result.risk_level === "High") {
      notifyThreat("Alerter flagged an email", "The open message shows phishing or spam warning signs. Open Alerter to review the reasons.");
    }
    return { ok: true, result };
  }

  function scheduleEmailScan() {
    const host = location.hostname.toLowerCase();
    if (!["mail.google.com", "outlook.live.com", "outlook.office.com", "outlook.office365.com"].includes(host)) return;
    clearTimeout(emailTimer);
    emailTimer = setTimeout(() => {
      if (host === "mail.google.com" && !extractOpenEmail().found) {
        void scanVisibleGmailInbox();
      } else {
        void scanOpenEmail(false).catch((error) => console.warn("Email scan skipped:", error.message));
      }
    }, 1300);
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "scan-email-now") return false;
    const email = extractOpenEmail();
    if (email.found) {
      sendResponse({ ...email, inbox_emails: [] });
      return false;
    }
    sendResponse({ ...email, inbox_emails: extractVisibleGmailPreviews() });
    return false;
  });

  document.addEventListener("click", highRiskClick, true);
  queuePageLinks();
  scheduleEmailScan();
  const observer = new MutationObserver((records) => {
    for (const record of records) for (const node of record.addedNodes || []) if (node.nodeType === 1) queuePageLinks(node);
    scheduleEmailScan();
  });
  if (document.documentElement) observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["href"] });
})();
