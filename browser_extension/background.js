const LOCAL_API = "http://127.0.0.1:8766";
if (typeof importScripts === "function") importScripts("threat-intel.js");

async function sendToLocal(path, payload) {
  const isHealthCheck = path === "/health";
  const response = await fetch(`${LOCAL_API}${path}`, isHealthCheck ? {
    method: "GET",
    cache: "no-store",
    credentials: "omit",
  } : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
    credentials: "omit",
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Local checker returned ${response.status}`);
  return result;
}

function broadcastAdProtection(enabled) {
  try {
    chrome.tabs.query({}, (tabs) => {
      if (chrome.runtime.lastError) return;
      for (const tab of tabs || []) {
        if (tab.id === undefined) continue;
        chrome.tabs.sendMessage(tab.id, { type: "ad-protection-state", enabled }, () => {
          void chrome.runtime.lastError;
        });
      }
    });
  } catch {}
}

function notifyThreat(message, sendResponse) {
  const title = String(message.title || "Alerter security warning").slice(0, 80);
  const body = String(message.message || "Alerter found signs of a risky link or email.").slice(0, 220);
  try {
    chrome.notifications.create("alerter-threat", {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/alerter-128.png"),
      title,
      message: body,
      priority: 2,
    }, (notificationId) => {
      const error = chrome.runtime.lastError;
      sendResponse(error
        ? { ok: false, error: error.message }
        : { ok: true, notificationId });
    });
    return true;
  } catch (error) {
    sendResponse({ ok: false, error: error.message || "Browser notification is unavailable." });
    return false;
  }
}

async function addThreatIntel(result) {
  if (!result || typeof result !== "object" || !result.host || result.host === "Unknown") return result;
  const finding = await self.AlerterThreatIntel.checkHost(result.host);
  if (!finding) return result;
  result.threat_intel = finding;
  result.risk_score = Math.max(Number(result.risk_score) || 0, 85);
  result.risk_level = "High";
  if (Array.isArray(result.signals)) {
    result.signals.unshift(`Domain appears in the active phishing list maintained by ${finding.source}`);
  }
  if (typeof result.category === "string" && !result.category.toLowerCase().includes("phishing")) {
    result.category = result.category === "No obvious match" ? "Phishing" : `${result.category}, Phishing`;
  }
  return result;
}

async function addThreatIntelToResponse(result) {
  if (Array.isArray(result)) return Promise.all(result.map(addThreatIntel));
  if (!result || typeof result !== "object") return result;
  if (result.status === "ok") result.threat_feed = await self.AlerterThreatIntel.status();
  if (result.host) return addThreatIntel(result);
  if (Array.isArray(result.urls)) {
    result.urls = await Promise.all(result.urls.map(addThreatIntel));
    const listed = result.urls.filter((item) => item?.threat_intel);
    if (listed.length) {
      result.risk_score = Math.max(Number(result.risk_score) || 0, 85);
      result.risk_level = "High";
      if (typeof result.category === "string" && !result.category.toLowerCase().includes("phishing")) {
        result.category = result.category === "No obvious match" ? "Phishing" : `${result.category}, Phishing`;
      }
      result.signals = Array.isArray(result.signals) ? result.signals : [];
      result.signals.unshift("A linked domain appears in the active community phishing list");
    }
  }
  return result;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  if (message?.type === "notify-threat") return notifyThreat(message, sendResponse);
  if (message?.type === "ad-blocker-status") {
    chrome.declarativeNetRequest.getEnabledRulesets()
      .then((ids) => sendResponse({ ok: true, enabled: ids.includes("basic_ads") }))
      .catch((error) => sendResponse({ ok: false, error: error.message || "Could not read ad-blocking status." }));
    return true;
  }
  if (message?.type === "set-ad-blocking") {
    const enabled = message.enabled === true;
    chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds: enabled ? ["basic_ads"] : [],
      disableRulesetIds: enabled ? [] : ["basic_ads"],
    })
      .then(() => {
        broadcastAdProtection(enabled);
        sendResponse({ ok: true, enabled });
      })
      .catch((error) => sendResponse({ ok: false, error: error.message || "Could not update ad-blocking settings." }));
    return true;
  }

  const routes = {
    "checker-status": ["/health", {}],
    "analyze-links": ["/analyze-links", { urls: message.urls || [] }],
    "analyze-url": ["/analyze-url", { url: message.url || "" }],
    "analyze-email": ["/analyze-email", { email: message.email || {} }],
    "analyze-screen": ["/analyze-screen", { image_data_url: message.image_data_url || "" }],
  };
  const route = routes[message?.type];
  if (!route) return false;

  sendToLocal(...route)
    .then(addThreatIntelToResponse)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: error.message || "The local checker is unavailable." }));
  return true;
});
