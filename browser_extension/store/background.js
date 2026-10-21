if (typeof importScripts === "function") importScripts("analyzer.js");

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
      sendResponse(error ? { ok: false, error: error.message } : { ok: true, notificationId });
    });
    return true;
  } catch (error) {
    sendResponse({ ok: false, error: error.message || "Browser notification is unavailable." });
    return false;
  }
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
      .then(() => sendResponse({ ok: true, enabled }))
      .catch((error) => sendResponse({ ok: false, error: error.message || "Could not update ad-blocking settings." }));
    return true;
  }

  try {
    if (message?.type === "checker-status") {
      sendResponse({ ok: true, result: { status: "ok", mode: "on-device", screen_ocr_supported: false } });
      return false;
    }
    if (message?.type === "analyze-url") {
      sendResponse({ ok: true, result: self.AlerterAnalyzer.analyzeUrl(message.url || "") });
      return false;
    }
    if (message?.type === "analyze-links") {
      const urls = Array.isArray(message.urls) ? message.urls.slice(0, 100) : [];
      sendResponse({ ok: true, result: urls.filter((url) => String(url || "").trim()).map(self.AlerterAnalyzer.analyzeUrl) });
      return false;
    }
    if (message?.type === "analyze-email") {
      const email = message.email && typeof message.email === "object" ? message.email : {};
      const result = self.AlerterAnalyzer.analyzeEmail(email);
      const checked = [];
      const seen = new Set();
      for (const item of (Array.isArray(email.link_pairs) ? email.link_pairs : []).slice(0, 20)) {
        const href = String(item?.href || "").trim().slice(0, 4096);
        if (href && !seen.has(href)) { seen.add(href); checked.push(self.AlerterAnalyzer.analyzeUrl(href)); }
      }
      result.urls = checked;
      const suspicious = checked.filter((item) => ["High", "Review"].includes(item.risk_level));
      if (suspicious.length) {
        const strongest = Math.max(...suspicious.map((item) => item.risk_score));
        result.risk_score = Math.min(100, result.risk_score + Math.min(35, Math.round(strongest * 0.45)));
        result.risk_level = result.risk_score >= 60 ? "High" : result.risk_score >= 30 ? "Review" : "Low";
        if (result.category === "No obvious match") result.category = "Phishing";
        result.signals.push(`Contains ${suspicious.length} link destination(s) with URL warning signs (highest score: ${strongest}/100)`);
      }
      sendResponse({ ok: true, result });
      return false;
    }
    if (message?.type === "analyze-screen") {
      sendResponse({ ok: false, error: "Screen-text scanning is not included in the store edition." });
      return false;
    }
  } catch (error) {
    sendResponse({ ok: false, error: error.message || "Alerter could not finish this check." });
    return false;
  }
  return false;
});
