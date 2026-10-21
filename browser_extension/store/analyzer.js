/* Self-contained, on-device heuristics for the Alerter browser-store edition. */
self.AlerterAnalyzer = (() => {
  const phishingPatterns = [
    [/\b(verify|confirm|restore|unlock|suspend(?:ed)?|secure)\b.{0,55}\b(account|password|identity|payment|mailbox)\b/i, 18, "Urgent account or identity verification language"],
    [/\b(password|login|sign in|credentials|one[- ]time code|security code)\b.{0,70}\b(click|link|reply|confirm|verify|submit|send)\b/i, 25, "Asks for credentials or a security code"],
    [/\b(click|tap|follow)\b.{0,35}\b(link|here|below)\b/i, 8, "Pressures the reader to follow a link"],
    [/\b(invoice|wire transfer|bank account|payment overdue|payment required|crypto(?:currency)?|wallet)\b/i, 12, "Requests or discusses a sensitive payment action"],
  ];
  const spamPatterns = [
    [/\b(congratulations|you(?:'|’)ve won|winner|prize|gift card|claim your|free entry)\b/i, 18, "Prize, giveaway, or free-reward language"],
    [/\b(earn money|make money fast|guaranteed income|work from home|get rich)\b/i, 16, "Unsolicited income or guaranteed-return language"],
    [/\b(limited time|act now|urgent|expires today|last chance)\b/i, 8, "Creates urgency to prompt a quick response"],
    [/\b(unsubscribe|buy now|order now|special offer|discount)\b/i, 6, "Promotional or bulk-message language"],
  ];
  const shorteners = new Set(["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at"]);
  const redirectParams = new Set(["url", "u", "target", "destination", "redirect", "redirecturl", "redirecturi", "redir", "next", "continue", "continueurl", "continueuri", "return", "returnto", "returnurl", "returnuri", "out", "to", "link", "goto", "forward", "forwardurl"]);
  const brands = {
    adobe: ["adobe.com"], amazon: ["amazon.com"], apple: ["apple.com", "icloud.com"],
    dropbox: ["dropbox.com"], docusign: ["docusign.com"], google: ["google.com", "gmail.com", "googlemail.com"],
    microsoft: ["microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"],
    netflix: ["netflix.com"], paypal: ["paypal.com", "paypalobjects.com"], yahoo: ["yahoo.com"],
  };
  const freeEmailDomains = new Set(["aol.com", "gmail.com", "googlemail.com", "hotmail.com", "icloud.com", "live.com", "outlook.com", "yahoo.com"]);
  const riskyExtensions = new Set(["ade", "adp", "app", "bat", "cab", "cmd", "com", "cpl", "exe", "hta", "img", "iso", "jar", "js", "jse", "lnk", "msi", "ps1", "scr", "vbe", "vbs", "wsf", "wsh"]);
  const reviewExtensions = new Set(["docm", "dotm", "html", "htm", "iso", "pptm", "xlam", "xlsm", "xltm"]);

  function domainAligns(first, second) {
    return Boolean(first && second) && (first === second || first.endsWith(`.${second}`) || second.endsWith(`.${first}`));
  }

  function emailDomain(address) {
    const value = String(address || "");
    const bracketed = value.match(/<([^<>]+)>/);
    const candidate = (bracketed?.[1] || value).trim();
    const at = candidate.lastIndexOf("@");
    return at >= 0 ? candidate.slice(at + 1).trim().replace(/^[ >.]+|[ >.]+$/g, "").toLowerCase() : "";
  }

  function parseUrl(value) {
    const candidate = String(value || "").trim();
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate) ? candidate : `https://${candidate}`);
  }

  function brandClaim(host) {
    const labels = host.toLowerCase().split(".").flatMap((label) => label.split("-"));
    const normalized = labels.map((label) => label.replace(/[01]/g, (digit) => digit === "0" ? "o" : "l").replace(/rn/g, "m").replace(/vv/g, "w"));
    for (const [brand, officialDomains] of Object.entries(brands)) {
      if (labels.includes(brand) || normalized.includes(brand)) {
        const official = officialDomains.some((domain) => host === domain || host.endsWith(`.${domain}`));
        return { brand, official, lookalike: !labels.includes(brand) };
      }
    }
    return null;
  }

  function looksLikeDomain(text) {
    const candidate = String(text || "").trim().replace(/^[<>()\[\]{},.;"']+|[<>()\[\]{},.;"']+$/g, "");
    if (!/^(?:https?:\/\/|www\.)/i.test(candidate) && !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[/?#]|$)/i.test(candidate)) return "";
    try { return (parseUrl(candidate).hostname || "").toLowerCase().replace(/\.$/, ""); }
    catch { return ""; }
  }

  function extractUrls(text) {
    const urls = [];
    const matches = String(text || "").match(/\b(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
    for (let candidate of matches) {
      candidate = candidate.replace(/[).,!?;:\]}'"]+$/g, "");
      if (/^www\./i.test(candidate)) candidate = `https://${candidate}`;
      if (candidate && !urls.includes(candidate)) urls.push(candidate);
    }
    return urls;
  }

  function analyzeUrl(value, depth = 0) {
    const url = String(value || "");
    const signals = [];
    let score = 0;
    let parsed;
    try { parsed = parseUrl(url); } catch { parsed = null; }
    const host = (parsed?.hostname || "").toLowerCase().replace(/\.$/, "");
    if (!host) return { url, host: "Unknown", risk_score: 35, risk_level: "Review", signals: ["The address could not be parsed as a normal web URL"] };

    if (url.length >= 100) { score += 15; signals.push("Unusually long web address"); }
    else if (url.length >= 75) { score += 8; signals.push("Long web address"); }

    const ipv4Parts = host.split(".");
    const isIpv4 = ipv4Parts.length === 4 && ipv4Parts.every((part) => /^\d+$/.test(part) && Number(part) <= 255);
    const isIpv6 = host.startsWith("[") && host.endsWith("]") && host.includes(":");
    if (isIpv4 || isIpv6) { score += 30; signals.push("Uses a raw IP address instead of a domain name"); }

    if (parsed.username || parsed.password) { score += 30; signals.push("Contains an @ sign in the address authority"); }
    if (host.includes("xn--")) { score += 20; signals.push("Contains an encoded internationalized domain name"); }

    const claim = brandClaim(host);
    if (claim && !claim.official) {
      score += claim.lookalike ? 35 : 30;
      signals.push(`${claim.lookalike ? "Resembles" : "Uses"} the ${claim.brand[0].toUpperCase()}${claim.brand.slice(1)} name on a domain outside its known domains`);
    }
    if (shorteners.has(host)) { score = Math.max(score + 15, 25); signals.push("Uses a link-shortening service that hides the destination"); }
    if (host.split(".").length >= 5) { score += 12; signals.push("Contains several nested subdomains"); }
    if (parsed.protocol.toLowerCase() !== "https:") { score += 8; signals.push("Does not use HTTPS"); }
    if (/(?:login|verify|account|secure|password|wallet|payment|signin)/i.test(host + parsed.pathname)) {
      score += 7; signals.push("Contains account or payment wording in the domain or path");
    }
    if (depth < 2) {
      for (const [key, target] of parsed.searchParams) {
        if (!redirectParams.has(key.toLowerCase().replace(/[_-]/g, "")) || !/^https?:\/\//i.test(target)) continue;
        const nested = analyzeUrl(target, depth + 1);
        if (nested.risk_score >= 25) {
          score = Math.max(score, nested.risk_score);
          signals.push(`Redirect parameter points to ${nested.host} (${nested.risk_level} risk)`);
          break;
        }
      }
    }
    score = Math.min(score, 100);
    const riskLevel = score >= 55 ? "High" : score >= 25 ? "Review" : "Low";
    if (!signals.length) signals.push("No obvious URL warning signs found by the local checks");
    return { url, host, risk_score: score, risk_level: riskLevel, signals };
  }

  function authHeaderFindings(value) {
    const findings = [];
    const checks = [
      ["spf", 14, 8, "The email authentication header reports SPF did not pass"],
      ["dkim", 14, 8, "The email authentication header reports DKIM did not pass"],
      ["dmarc", 22, 10, "The email authentication header reports DMARC did not pass"],
    ];
    for (const [method, failPoints, softfailPoints, label] of checks) {
      const match = String(value || "").match(new RegExp(`(?<![a-z0-9_-])${method}\\s*=\\s*([a-z]+)`, "i"));
      if (!match) continue;
      const status = match[1].toLowerCase();
      if (["fail", "permerror"].includes(status)) findings.push([method, failPoints, label]);
      else if (status === "softfail") findings.push([method, softfailPoints, `The email authentication header reports a ${method.toUpperCase()} soft failure`]);
    }
    return findings;
  }

  function analyzeEmail(email = {}) {
    const subject = String(email.subject || "");
    const sender = String(email.sender || "");
    const replyTo = String(email.reply_to || "");
    const body = String(email.body || "");
    const senderName = String(email.sender_name || "");
    const returnPath = String(email.return_path || "");
    const authenticationResults = String(email.authentication_results || "");
    const attachmentNames = Array.isArray(email.attachment_names) ? email.attachment_names : [];
    const linkPairs = Array.isArray(email.link_pairs) ? email.link_pairs : [];
    const content = `${subject} ${body}`;
    const signals = [];
    const kinds = new Set();
    let score = 0;
    for (const [pattern, points, label] of phishingPatterns) if (pattern.test(content)) { score += points; signals.push(label); kinds.add("Phishing"); }
    for (const [pattern, points, label] of spamPatterns) if (pattern.test(content)) { score += points; signals.push(label); kinds.add("Spam"); }

    const senderDomain = emailDomain(sender);
    const replyDomain = emailDomain(replyTo);
    const returnPathDomain = emailDomain(returnPath);
    if (senderDomain && replyDomain && !domainAligns(senderDomain, replyDomain)) { score += 25; signals.push("Reply-to address uses a different domain from the sender"); kinds.add("Phishing"); }
    if (senderDomain && returnPathDomain && !domainAligns(senderDomain, returnPathDomain)) { score += 16; signals.push("Return-Path domain does not align with the sender domain"); kinds.add("Phishing"); }
    for (const [method, points, signal] of authHeaderFindings(authenticationResults)) { score += points; signals.push(signal); kinds.add("Phishing"); }

    for (const [brand, officialDomains] of Object.entries(brands)) {
      if (new RegExp(`\\b${brand}\\b`, "i").test(senderName) && (
        freeEmailDomains.has(senderDomain) || !officialDomains.some((domain) => senderDomain === domain || senderDomain.endsWith(`.${domain}`))
      )) {
        score += 30;
        signals.push(`Sender display name claims ${brand[0].toUpperCase()}${brand.slice(1)}, but its email domain is different`);
        kinds.add("Phishing");
        break;
      }
    }

    for (const link of linkPairs) {
      const href = String(link?.href || "").trim();
      const visibleText = String(link?.text || "").trim();
      const scheme = href.includes(":") ? href.split(":", 1)[0].toLowerCase() : "";
      if (["javascript", "data", "vbscript"].includes(scheme)) { score += 35; signals.push(`Contains an embedded link using the ${scheme}: scheme`); kinds.add("Phishing"); continue; }
      const visibleHost = looksLikeDomain(visibleText);
      const destinationHost = href ? analyzeUrl(href).host : "";
      if (visibleHost && !["", "Unknown"].includes(destinationHost) && !domainAligns(visibleHost, destinationHost)) {
        score += 30;
        signals.push(`Visible link text names ${visibleHost}, but the link points to ${destinationHost}`);
        kinds.add("Phishing");
      }
    }

    for (const filename of attachmentNames) {
      const match = String(filename).toLowerCase().match(/(?:\.([a-z0-9]{1,10}))+$/);
      const suffix = match ? match[1] : "";
      if (riskyExtensions.has(suffix)) { score += 30; signals.push(`Attachment name ends in a potentially dangerous .${suffix} file type`); kinds.add("Phishing"); }
      else if (reviewExtensions.has(suffix)) { score += 18; signals.push(`Attachment uses an active-content file type (.${suffix})`); kinds.add("Phishing"); }
    }

    const urls = extractUrls(content).slice(0, 20).map(analyzeUrl);
    if (urls.length) {
      const highestUrlRisk = Math.max(...urls.map((item) => item.risk_score));
      if (highestUrlRisk >= 25) {
        score += Math.min(35, Math.round(highestUrlRisk * 0.45));
        signals.push(`Contains a link with URL warning signs (highest URL score: ${highestUrlRisk}/100)`);
        kinds.add("Phishing");
      }
    }
    score = Math.min(score, 100);
    if (!signals.length) signals.push("No obvious spam or phishing indicators found by the local checks");
    return {
      risk_score: score,
      risk_level: score >= 60 ? "High" : score >= 30 ? "Review" : "Low",
      category: kinds.size ? [...kinds].sort().join(", ") : "No obvious match",
      signals,
      urls,
      sender,
      sender_name: senderName,
      subject,
      attachment_names: attachmentNames,
      notice: "A Low score is not proof that a message is safe. These checks do not verify sender identity or visit links.",
    };
  }

  return { analyzeUrl, analyzeEmail };
})();
