/* MAIN-world guard: stop window.open calls aimed at known ad/pop-under hosts. */
(() => {
  if (window.__alerterPopupGuardInstalled) return;
  window.__alerterPopupGuardInstalled = true;

  const adHosts = new Set([
    "doubleclick.net", "googleadservices.com", "googlesyndication.com", "adnxs.com",
    "ag.lockywinder.com", "js.braxybanty.com", "tryembed.us.cc",
    "adsrvr.org", "taboola.com", "outbrain.com", "criteo.com", "adform.net",
    "adroll.com", "revcontent.com", "zedo.com", "popads.net", "popcash.net",
    "propellerads.com", "adcash.com", "trafficjunky.net", "exoclick.com",
    "hilltopads.net", "adsterra.com", "smartadserver.com", "advertising.com",
  ]);
  let enabled = true;
  window.addEventListener("alerter:set-ad-protection", (event) => {
    enabled = event.detail === true;
  });

  function isAdDestination(value) {
    if (typeof value !== "string" || !value.trim()) return false;
    try {
      const host = new URL(value, location.href).hostname.toLowerCase().replace(/\.$/, "");
      let candidate = host;
      while (candidate.includes(".")) {
        if (adHosts.has(candidate)) return true;
        candidate = candidate.slice(candidate.indexOf(".") + 1);
      }
    } catch {}
    return false;
  }

  const nativeOpen = window.open;
  window.open = function alerterGuardedOpen(url, target, features) {
    if (enabled && isAdDestination(url)) {
      try {
        const host = new URL(url, location.href).hostname.toLowerCase();
        window.dispatchEvent(new CustomEvent("alerter:ad-popup-blocked", { detail: { host } }));
      } catch {}
      return null;
    }
    return Reflect.apply(nativeOpen, this, arguments);
  };
})();
