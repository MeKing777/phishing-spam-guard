const LOCAL_API = "http://127.0.0.1:8766";

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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  if (message?.type === "notify-threat") return notifyThreat(message, sendResponse);

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
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: error.message || "The local checker is unavailable." }));
  return true;
});
