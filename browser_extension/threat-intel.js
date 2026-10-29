/* On-device reputation lookup using the community-maintained Phishing.Database feed. */
self.AlerterThreatIntel = (() => {
  const FEED_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
  const FEED_NAME = "Phishing.Database active-domain community feed";
  const STORAGE_KEY = "alerterThreatIntelCacheV1";
  const ALARM_NAME = "alerter-threat-feed-refresh";
  const REFRESH_INTERVAL_MS = 12 * 60 * 60 * 1000;
  const MAX_STALE_MS = 7 * 24 * 60 * 60 * 1000;
  const MAX_FEED_CHARS = 16 * 1024 * 1024;
  const MAX_DOMAINS = 250_000;
  const MIN_DOMAINS = 1_000;
  const broadHostsToSkip = new Set([
    "com", "net", "org", "edu", "gov", "mil", "int", "uk", "co.uk", "org.uk",
    "ac.uk", "gov.uk", "in", "co.in", "org.in", "gov.in", "us", "ca", "au",
    "com.au", "org.au", "de", "fr", "jp", "co.jp", "cn", "ru", "br", "com.br",
    "io", "dev", "app", "xyz", "info", "biz", "github.io", "pages.dev",
    "workers.dev", "blogspot.com", "wordpress.com", "netlify.app", "vercel.app",
    "firebaseapp.com", "web.app", "wixsite.com", "herokuapp.com", "onrender.com",
  ]);

  let cachedRecord = null;
  let cachedDomains = null;
  let loadPromise = null;
  let refreshPromise = null;

  function storageGet() {
    return new Promise((resolve, reject) => {
      chrome.storage.local.get(STORAGE_KEY, (values) => {
        const error = chrome.runtime.lastError;
        if (error) reject(new Error(error.message));
        else resolve(values?.[STORAGE_KEY] || null);
      });
    });
  }

  function storageSet(record) {
    return new Promise((resolve, reject) => {
      chrome.storage.local.set({ [STORAGE_KEY]: record }, () => {
        const error = chrome.runtime.lastError;
        if (error) reject(new Error(error.message));
        else resolve();
      });
    });
  }

  function normalizeFeedLine(line) {
    let candidate = String(line || "").trim();
    if (!candidate || candidate.startsWith("#")) return "";
    if (candidate.startsWith("||")) candidate = candidate.slice(2).replace(/\^.*$/, "");
    const parts = candidate.split(/\s+/);
    if (parts.length > 1 && /^(?:0\.0\.0\.0|127\.0\.0\.1|::1)$/.test(parts[0])) candidate = parts[1];
    candidate = candidate.toLowerCase().replace(/\.$/, "");
    if (!candidate || candidate.includes("*") || candidate.includes("/") || candidate.length > 253) return "";
    let host;
    try {
      const parsed = new URL(`https://${candidate}`);
      if (parsed.pathname !== "/" || parsed.username || parsed.password || parsed.port) return "";
      host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    } catch { return ""; }
    if (!host.includes(".") || broadHostsToSkip.has(host)) return "";
    if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) return "";
    if (/^\d+(?:\.\d+){3}$/.test(host)) return "";
    return host;
  }

  function useRecord(record) {
    if (!record || !Array.isArray(record.domains) || !Number.isFinite(record.updated_at)) return null;
    const unique = [...new Set(record.domains.filter((host) => typeof host === "string"))];
    if (!unique.length || unique.length > MAX_DOMAINS) return null;
    cachedRecord = { source: FEED_NAME, updated_at: record.updated_at, count: unique.length, domains: unique };
    cachedDomains = new Set(unique);
    return cachedRecord;
  }

  async function loadCache() {
    if (cachedRecord) return cachedRecord;
    if (loadPromise) return loadPromise;
    loadPromise = storageGet()
      .then((record) => useRecord(record))
      .catch(() => null)
      .finally(() => { loadPromise = null; });
    return loadPromise;
  }

  async function refresh(force = false) {
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      const previous = await loadCache();
      if (!force && previous && Date.now() - previous.updated_at < REFRESH_INTERVAL_MS) return previous;
      try {
        const response = await fetch(FEED_URL, {
          method: "GET",
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
          headers: { Accept: "text/plain" },
        });
        if (!response.ok) throw new Error(`Threat feed returned ${response.status}`);
        const declaredLength = Number(response.headers.get("content-length") || 0);
        if (declaredLength > MAX_FEED_CHARS) throw new Error("Threat feed exceeded its size limit");
        const text = await response.text();
        if (text.length > MAX_FEED_CHARS) throw new Error("Threat feed exceeded its size limit");
        const domains = [...new Set(text.split(/\r?\n/).map(normalizeFeedLine).filter(Boolean))];
        if (domains.length < MIN_DOMAINS || domains.length > MAX_DOMAINS) throw new Error("Threat feed did not pass validation");
        domains.sort();
        const record = { source: FEED_NAME, updated_at: Date.now(), count: domains.length, domains };
        await storageSet(record);
        return useRecord(record);
      } catch {
        return previous;
      }
    })().finally(() => { refreshPromise = null; });
    return refreshPromise;
  }

  async function checkHost(value) {
    const host = String(value || "").trim().toLowerCase().replace(/\.$/, "");
    if (!host || host === "unknown") return null;
    const record = await refresh(false);
    if (!record || Date.now() - record.updated_at > MAX_STALE_MS || !cachedDomains) return null;
    let candidate = host;
    while (candidate.includes(".")) {
      if (cachedDomains.has(candidate)) {
        return { type: "phishing", source: record.source, updated_at: record.updated_at, matched_domain: candidate };
      }
      candidate = candidate.slice(candidate.indexOf(".") + 1);
    }
    return null;
  }

  async function status() {
    const record = await loadCache();
    if (!record || Date.now() - record.updated_at > MAX_STALE_MS) {
      return { available: false, source: FEED_NAME, updated_at: record?.updated_at || null, count: 0 };
    }
    return { available: true, source: record.source, updated_at: record.updated_at, count: record.count };
  }

  function scheduleRefresh() {
    try { chrome.alarms.create(ALARM_NAME, { periodInMinutes: 12 * 60 }); } catch {}
  }

  try {
    scheduleRefresh();
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm?.name === ALARM_NAME) void refresh(true);
    });
    chrome.runtime.onInstalled.addListener(() => {
      scheduleRefresh();
      void refresh(true);
    });
    chrome.runtime.onStartup.addListener(() => void refresh(false));
  } catch {}

  return { checkHost, refresh, status, source: FEED_NAME };
})();
