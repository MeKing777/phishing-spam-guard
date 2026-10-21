const pageUrl = document.getElementById("page-url");
const resultBox = document.getElementById("result");
const notice = document.getElementById("notice");
const service = document.getElementById("service");
const serviceLabel = document.getElementById("service-label");
const checkButton = document.getElementById("check");
const emailButton = document.getElementById("scan-email");
const screenButton = document.getElementById("scan-screen");
const screenHelp = document.getElementById("scan-help");
const adBlockerButton = document.getElementById("ad-blocker");
const mailHosts = new Set(["mail.google.com", "outlook.live.com", "outlook.office.com", "outlook.office365.com"]);
let activeTab;

chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
  activeTab = tabs?.[0];
  const activeUrl = activeTab?.url || "";
  if (!activeUrl || !/^https?:\/\//i.test(activeUrl)) {
    pageUrl.textContent = "Open a regular website to scan it.";
    checkButton.disabled = true;
    screenButton.disabled = true;
    return;
  }
  screenButton.disabled = false;
  pageUrl.textContent = activeUrl;
  try {
    const host = new URL(activeUrl).hostname.toLowerCase();
    emailButton.disabled = !mailHosts.has(host);
    emailButton.textContent = host === "mail.google.com" ? "Rescan visible emails" : "Rescan open email";
  }
  catch { emailButton.disabled = true; }
});

function clearResult() {
  resultBox.replaceChildren();
  notice.classList.remove("error");
  notice.textContent = "Checks run on this computer. A low-risk result does not prove a page or message is safe.";
}

function showError(error) {
  resultBox.innerHTML = '<div class="empty"><strong>Scan could not finish</strong></div>';
  notice.classList.add("error");
  notice.textContent = error || "Alerter could not finish this check. Try again.";
}

function showResult(result) {
  resultBox.replaceChildren();
  const level = String(result.risk_level || "Review").toLowerCase();
  const report = document.createElement("section");
  report.className = `report ${level}`;
  const head = document.createElement("div");
  head.className = "result-head";
  const pill = document.createElement("span");
  pill.className = "pill";
  pill.textContent = `${result.risk_level || "Review"} risk`;
  const score = document.createElement("span");
  score.className = "score";
  score.textContent = `${result.risk_score ?? "—"}/100`;
  head.append(pill, score);

  const category = document.createElement("div");
  category.className = "category";
  category.textContent = result.category || result.host || "URL scan";
  report.append(head, category);
  if (result.source_label) {
    const source = document.createElement("div");
    source.className = "subject";
    source.textContent = result.source_label;
    report.append(source);
  }
  for (const [label, value, className] of [
    ["Subject", result.subject, "subject"],
    ["From", result.sender_name || result.sender, "sender"],
  ]) {
    if (!value) continue;
    const line = document.createElement("div");
    line.className = className;
    line.textContent = `${label}: ${value}`;
    report.append(line);
  }

  const signals = (result.signals || []).slice(0, 6);
  if (signals.length) {
    const list = document.createElement("ul");
    list.className = "signals";
    for (const signal of signals) {
      const item = document.createElement("li");
      item.textContent = signal;
      list.append(item);
    }
    report.append(list);
  }
  resultBox.append(report);

  if (result.urls?.length) {
    const title = document.createElement("div");
    title.className = "links-title";
    title.textContent = result.source_label?.toLowerCase().includes("visible screen")
      ? "Links detected in this screen"
      : result.subject || result.sender ? "Links in this email" : "Links detected in this scan";
    const list = document.createElement("div");
    list.className = "links";
    for (const link of result.urls.slice(0, 12)) {
      const item = document.createElement("div");
      item.className = "link";
      const host = document.createElement("strong");
      host.textContent = link.host || "Unknown destination";
      item.append(host, document.createTextNode(` · ${link.risk_level} (${link.risk_score}/100)`));
      list.append(item);
    }
    resultBox.append(title, list);
  }
}

function showInboxPreviews(items) {
  resultBox.replaceChildren();
  const riskyCount = items.filter(({ result }) => result.risk_level === "High").length;
  const summary = document.createElement("section");
  summary.className = `report ${riskyCount ? "high" : "review"}`;
  const heading = document.createElement("div");
  heading.className = "category";
  heading.textContent = `${items.length} visible message preview${items.length === 1 ? "" : "s"} scanned`;
  const detail = document.createElement("div");
  detail.className = "subject";
  detail.textContent = riskyCount
    ? `${riskyCount} preview${riskyCount === 1 ? " has" : "s have"} high-risk warning signs.`
    : "No high-risk preview was detected in the visible messages.";
  summary.append(heading, detail);
  resultBox.append(summary);

  for (const { email, result } of items) {
    const level = String(result.risk_level || "Review").toLowerCase();
    const report = document.createElement("section");
    report.className = `report ${level}`;
    const head = document.createElement("div");
    head.className = "result-head";
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.textContent = `${result.risk_level || "Review"} risk`;
    const score = document.createElement("span");
    score.className = "score";
    score.textContent = `${result.risk_score ?? "—"}/100`;
    head.append(pill, score);
    const subject = document.createElement("div");
    subject.className = "category";
    subject.textContent = email.subject || "(No subject shown)";
    const sender = document.createElement("div");
    sender.className = "sender";
    sender.textContent = `From: ${email.sender_name || email.sender || "Sender not shown"}`;
    const previewTag = document.createElement("div");
    previewTag.className = "subject";
    previewTag.textContent = "Preview only — open this message for a full scan of its links and content.";
    report.append(head, subject, sender, previewTag);
    const signals = (result.signals || []).slice(0, 2);
    if (signals.length) {
      const list = document.createElement("ul");
      list.className = "signals";
      for (const signal of signals) {
        const item = document.createElement("li");
        item.textContent = signal;
        list.append(item);
      }
      report.append(list);
    }
    resultBox.append(report);
  }
  notice.textContent = "Only previews currently visible in your mail app were checked. Low risk does not guarantee that a message is safe.";
}

async function runLocalCheck(type, payload = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...payload });
  if (!response?.ok) throw new Error(response?.error || "Alerter could not finish this check.");
  return response.result;
}

function captureVisibleTab(windowId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.captureVisibleTab(windowId, { format: "jpeg", quality: 55 }, (imageDataUrl) => {
      const error = chrome.runtime.lastError;
      if (error) reject(new Error(error.message));
      else if (!imageDataUrl) reject(new Error("The browser did not provide a screenshot. Try the scan again on a normal web page."));
      else resolve(imageDataUrl);
    });
  });
}

async function updateAdBlockerStatus() {
  adBlockerButton.disabled = true;
  try {
    const response = await chrome.runtime.sendMessage({ type: "ad-blocker-status" });
    if (!response?.ok) throw new Error(response?.error || "Could not read ad-blocking status.");
    adBlockerButton.setAttribute("aria-checked", String(response.enabled));
  } catch (error) {
    adBlockerButton.setAttribute("aria-checked", "false");
    adBlockerButton.title = error.message;
  } finally {
    adBlockerButton.disabled = false;
  }
}

async function updateServiceStatus() {
  try {
    const status = await runLocalCheck("checker-status");
    service.classList.add("online");
    if (status?.mode === "on-device") {
      serviceLabel.textContent = "On-device checks ready";
      screenButton.hidden = true;
      screenHelp.hidden = true;
      const footer = document.getElementById("footer");
      if (footer) footer.textContent = "Alerter checks page addresses and visible email text on this device. Scan content is not sent to an Alerter server.";
      return;
    }
    serviceLabel.textContent = "Local checker on";
    if (status?.screen_ocr_available) {
      screenHelp.textContent = "Captures only the visible tab after you click. Text is read and checked on this computer.";
    } else {
      screenHelp.textContent = "Screen reading needs Tesseract OCR installed. The captured image is processed on this computer.";
    }
  } catch {
    service.classList.remove("online");
    serviceLabel.textContent = "Checker offline";
    notice.textContent = "Alerter checks are unavailable. Reload the extension and try again.";
  }
}

adBlockerButton.addEventListener("click", async () => {
  const enabled = adBlockerButton.getAttribute("aria-checked") !== "true";
  adBlockerButton.disabled = true;
  try {
    const response = await chrome.runtime.sendMessage({ type: "set-ad-blocking", enabled });
    if (!response?.ok) throw new Error(response?.error || "Could not update ad-blocking settings.");
    adBlockerButton.setAttribute("aria-checked", String(response.enabled));
    adBlockerButton.title = "Block common ads and trackers";
  } catch (error) {
    notice.classList.add("error");
    notice.textContent = error.message || "Could not update ad-blocking settings.";
  } finally {
    adBlockerButton.disabled = false;
  }
});

checkButton.addEventListener("click", async () => {
  if (!activeTab?.url) return;
  checkButton.disabled = true;
  checkButton.textContent = "Scanning…";
  clearResult();
  resultBox.innerHTML = '<div class="empty"><strong>Checking this address</strong>Running phishing checks on this device…</div>';
  try { showResult(await runLocalCheck("analyze-url", { url: activeTab.url })); }
  catch (error) { showError(error.message); }
  finally { checkButton.disabled = false; checkButton.textContent = "Scan this page"; }
});

screenButton.addEventListener("click", async () => {
  if (!activeTab?.id || !activeTab?.url || !/^https?:\/\//i.test(activeTab.url)) return;
  screenButton.disabled = true;
  screenButton.textContent = "Capturing and reading…";
  clearResult();
  resultBox.innerHTML = '<div class="empty"><strong>Reading the visible screen</strong>Capturing this tab and checking its readable text on your computer…</div>';
  try {
    const imageDataUrl = await captureVisibleTab(activeTab.windowId);
    showResult(await runLocalCheck("analyze-screen", { image_data_url: imageDataUrl }));
  } catch (error) { showError(error.message || "Screen scan could not finish. Try again."); }
  finally {
    screenButton.disabled = false;
    screenButton.textContent = "Scan visible screen";
  }
});

emailButton.addEventListener("click", async () => {
  if (!activeTab?.id) return;
  emailButton.disabled = true;
  emailButton.textContent = "Scanning…";
  clearResult();
  resultBox.innerHTML = '<div class="empty"><strong>Scanning email</strong>Checking the open message or visible Gmail previews on this device…</div>';
  try {
    const scanData = await chrome.tabs.sendMessage(activeTab.id, { type: "scan-email-now" });
    if (scanData?.found) {
      showResult(await runLocalCheck("analyze-email", { email: scanData }));
    } else if (scanData?.inbox_emails?.length) {
      const items = await Promise.all(scanData.inbox_emails.map(async (email) => ({
        email,
        result: await runLocalCheck("analyze-email", { email }),
      })));
      showInboxPreviews(items);
    } else if (scanData?.supported && activeTab.url.includes("mail.google.com")) {
      throw new Error("No visible Gmail messages were found. Open the Inbox and refresh the page, then try again.");
    } else {
      throw new Error("Open a message in Gmail or Outlook, then try again. If the page was already open, refresh it first.");
    }
  } catch (error) { showError(error.message || "Refresh the email page and try again."); }
  finally {
    emailButton.disabled = false;
    try { emailButton.textContent = new URL(activeTab?.url || "").hostname === "mail.google.com" ? "Rescan visible emails" : "Rescan open email"; }
    catch { emailButton.textContent = "Rescan open email"; }
  }
});

void updateServiceStatus();
void updateAdBlockerStatus();
