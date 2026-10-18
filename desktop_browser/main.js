const { app, BrowserWindow, WebContentsView, ipcMain, dialog, session } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const tabs = new Map();
const pending = new Map();
let win;
let activeId;
let nextTab = 1;
let nextRequest = 1;
let scanner;
let protection = true;
let overlayVisible = false;
let chromeHeight = 104;
let linkPoll;
const mailHosts = new Set(["mail.google.com", "outlook.live.com", "outlook.office.com", "outlook.office365.com"]);

function startScanner() {
  if (scanner) return;
  const customPython = process.env.PHISHING_GUARD_PYTHON;
  const executable = customPython || (process.platform === "win32" ? "python" : "python3");
  const args = [path.join(root, "src", "browser_scan_worker.py")];
  const paths = [".runtime_packages", ".runtime_ml", ".runtime_packages_extra", ".runtime_googleauth", "."]
    .map((item) => path.resolve(root, item)).join(path.delimiter);
  scanner = spawn(executable, args, {
    cwd: root,
    windowsHide: true,
    env: { ...process.env, PYTHONPATH: [paths, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter) },
  });
  let buffer = "";
  scanner.stdout.setEncoding("utf8");
  scanner.stdout.on("data", (chunk) => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, end).trim();
      buffer = buffer.slice(end + 1);
      if (!line) continue;
      try {
        const response = JSON.parse(line);
        const task = pending.get(response.id);
        if (!task) continue;
        pending.delete(response.id);
        clearTimeout(task.timer);
        response.error ? task.reject(new Error(response.error)) : task.resolve(response.result);
      } catch (error) { console.warn("Invalid local scan response:", error.message); }
    }
  });
  scanner.stderr.setEncoding("utf8");
  scanner.stderr.on("data", (chunk) => console.warn("Local scanner:", chunk.trim()));
  scanner.on("error", (error) => failPending(error));
  scanner.on("close", (code) => { failPending(new Error(`Local Python scanner stopped (${code ?? "unknown"}).`)); scanner = null; });
}

function failPending(error) {
  for (const [id, task] of pending) {
    clearTimeout(task.timer);
    task.reject(error);
    pending.delete(id);
  }
}

function scan(request) {
  startScanner();
  if (!scanner || !scanner.stdin.writable) return Promise.reject(new Error("Local Python scanner is unavailable."));
  const id = nextRequest++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("Local scan timed out.")); }, 12000);
    pending.set(id, { resolve, reject, timer });
    scanner.stdin.write(`${JSON.stringify({ id, request })}\n`, (error) => {
      if (error) { pending.delete(id); clearTimeout(timer); reject(error); }
    });
  });
}

function normalizeAddress(raw) {
  const value = String(raw || "").trim();
  if (!value) throw new Error("Enter a website address or search term.");
  if (/^(javascript|data|file|vbscript):/i.test(value)) throw new Error("This browser blocks active-content and local-file addresses.");
  if (/^https?:\/\//i.test(value)) return value;
  if (/^[\w.-]+\.[a-z]{2,}(\/|$)/i.test(value)) return `https://${value}`;
  return `https://www.google.com/search?q=${encodeURIComponent(value)}`;
}

function isMailPage(address) {
  try { return mailHosts.has(new URL(address).hostname.toLowerCase()); } catch { return false; }
}

function activeTab() { return tabs.get(activeId); }

function updateLayout() {
  if (!win || win.isDestroyed()) return;
  const { width, height } = win.getContentBounds();
  for (const tab of tabs.values()) {
    const visible = tab.id === activeId && !overlayVisible && /^https?:/i.test(tab.url);
    tab.view.setBounds({ x: 0, y: chromeHeight, width, height: visible ? Math.max(0, height - chromeHeight) : 0 });
  }
}

function stateSnapshot() {
  return {
    protectionEnabled: protection,
    activeTabId: activeId,
    tabs: Array.from(tabs.values()).map((tab) => ({
      id: tab.id,
      title: tab.view.webContents.getTitle() || (tab.url ? (() => { try { return new URL(tab.url).hostname; } catch { return "New tab"; } })() : "New tab"),
      url: tab.url,
      active: tab.id === activeId,
      canGoBack: tab.view.webContents.canGoBack(),
      canGoForward: tab.view.webContents.canGoForward(),
      loading: tab.view.webContents.isLoading(),
      mailPage: isMailPage(tab.url),
    })),
  };
}

function publishState() {
  if (win && !win.isDestroyed()) win.webContents.send("browser:state", stateSnapshot());
}

async function warnHighRisk(url, result) {
  if (result?.risk_level !== "High") return true;
  const signals = (result.signals || []).slice(0, 5).map((signal) => `• ${signal}`).join("\n");
  const choice = await dialog.showMessageBox(win, {
    type: "warning",
    title: "Suspicious link blocked",
    message: `The local checker found strong warning signs for:\n${url}`,
    detail: `${signals || "High URL risk score."}\n\nChecks can make mistakes. Continue only if you trust this address.`,
    buttons: ["Stay here", "Open anyway"],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
  });
  return choice.response === 1;
}

async function navigate(tab, rawAddress) {
  if (!tab || tab.view.webContents.isDestroyed()) return;
  let url;
  try { url = normalizeAddress(rawAddress); }
  catch (error) { win.webContents.send("browser:status", { kind: "error", message: error.message }); return; }
  if (protection) {
    try {
      const result = await scan({ mode: "url", url });
      if (!(await warnHighRisk(url, result))) return;
    } catch (error) {
      win.webContents.send("browser:status", { kind: "error", message: `The local safety check failed, so this address was not opened: ${error.message}` });
      return;
    }
  }
  tab.approved.add(url);
  tab.url = url;
  updateLayout();
  publishState();
  try { await tab.view.webContents.loadURL(url); }
  catch (error) { win.webContents.send("browser:status", { kind: "error", message: `Could not open the page: ${error.message}` }); }
}

async function checkClickedLink(tab, url) {
  if (!protection || !/^https?:/i.test(url) || tab.checking) return;
  if (tab.approved.has(url)) { tab.approved.delete(url); return; }
  tab.view.webContents.stop();
  tab.checking = true;
  try {
    const result = await scan({ mode: "url", url });
    if (await warnHighRisk(url, result)) {
      tab.approved.add(url);
      await tab.view.webContents.loadURL(url);
    } else {
      win.webContents.send("browser:status", { kind: "safe", message: "Suspicious navigation was stopped." });
    }
  } catch (error) {
    win.webContents.send("browser:status", { kind: "error", message: `The local safety check failed, so the link was not opened: ${error.message}` });
  } finally { tab.checking = false; }
}

function createTab(rawAddress = "") {
  const id = `tab-${nextTab++}`;
  const view = new WebContentsView({ webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true, spellcheck: true } });
  const tab = { id, view, url: "", approved: new Set(), checking: false, scanning: false };
  tabs.set(id, tab);
  win.contentView.addChildView(view);
  activeId = id;
  view.webContents.setWindowOpenHandler(({ url }) => { const child = createTab(); if (url) void navigate(child, url); return { action: "deny" }; });
  view.webContents.on("will-navigate", (event, url) => {
    if (!/^https?:/i.test(url)) { event.preventDefault(); return; }
    if (!protection || tab.approved.has(url)) { tab.approved.delete(url); return; }
    event.preventDefault();
    void checkClickedLink(tab, url);
  });
  view.webContents.on("will-redirect", (event, url) => {
    if (!/^https?:/i.test(url)) { event.preventDefault(); return; }
    if (!protection || tab.approved.has(url)) { tab.approved.delete(url); return; }
    event.preventDefault();
    void checkClickedLink(tab, url);
  });
  view.webContents.on("did-navigate", (_event, url) => { tab.url = /^https?:/i.test(url) ? url : ""; updateLayout(); publishState(); });
  view.webContents.on("did-navigate-in-page", (_event, url) => { tab.url = /^https?:/i.test(url) ? url : ""; publishState(); });
  view.webContents.on("page-title-updated", publishState);
  view.webContents.on("did-finish-load", () => { tab.url = view.webContents.getURL(); updateLayout(); publishState(); if (protection) void scanPageLinks(tab); });
  view.webContents.on("render-process-gone", (_event, details) => win.webContents.send("browser:status", { kind: "error", message: `A page stopped unexpectedly (${details.reason}).` }));
  updateLayout();
  publishState();
  if (rawAddress) void navigate(tab, rawAddress);
  return tab;
}

const observerScript = `(() => {
  if (window.__guardLinks) return;
  const state = window.__guardLinks = { queue: new Map(), seen: new Set(), ratings: new Map() };
  const collect = (root) => {
    if (!root) return;
    const links = [];
    if (root.nodeType === 1 && root.matches?.('a[href]')) links.push(root);
    if (root.querySelectorAll) links.push(...root.querySelectorAll('a[href]'));
    for (const a of links) {
      try {
        const url = new URL(a.href, location.href);
        if (!['http:', 'https:'].includes(url.protocol) || state.seen.has(url.href)) continue;
        state.seen.add(url.href);
        state.queue.set(url.href, { url: url.href, text: (a.innerText || a.getAttribute('aria-label') || '').trim().slice(0, 160) });
      } catch {}
    }
  };
  collect(document.documentElement);
  new MutationObserver((records) => records.forEach((record) => { if (record.type === 'attributes') collect(record.target); for (const node of record.addedNodes || []) collect(node); }))
    .observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] });
})()`;
const takeLinksScript = `(() => { const state = window.__guardLinks; if (!state) return []; const links = Array.from(state.queue.values()).slice(0, 60); links.forEach((link) => state.queue.delete(link.url)); return links; })()`;

async function scanPageLinks(tab) {
  if (!tab || tab.id !== activeId || tab.scanning || !protection || !tab.url) return;
  tab.scanning = true;
  try {
    await tab.view.webContents.executeJavaScript(observerScript, true);
    const links = await tab.view.webContents.executeJavaScript(takeLinksScript, true);
    if (!Array.isArray(links) || !links.length) return;
    const results = await scan({ mode: "links", urls: links.map((link) => link.url) });
    const resultJson = JSON.stringify(results).replace(/</g, "\\u003c");
    const applyScript = `(() => {
      const state = window.__guardLinks; if (!state) return 0;
      const results = ${resultJson}; let flagged = 0;
      for (const result of results) { state.ratings.set(result.url, result); if (result.risk_level === 'High' || result.risk_level === 'Review') flagged++; }
      if (!document.getElementById('__guardLinkCss')) { const style = document.createElement('style'); style.id='__guardLinkCss'; style.textContent='a[data-guard-risk="high"]{outline:2px solid #c43b43!important;outline-offset:2px!important;background:#fff0f0!important;border-radius:3px!important}a[data-guard-risk="review"]{outline:2px solid #b76e00!important;outline-offset:2px!important;background:#fff7e7!important;border-radius:3px!important}'; (document.head||document.documentElement).appendChild(style); }
      for (const a of document.querySelectorAll('a[href]')) { try { const r=state.ratings.get(new URL(a.href,location.href).href); if (!r || !['High','Review'].includes(r.risk_level)) continue; a.dataset.guardRisk=r.risk_level.toLowerCase(); a.title='Guard: '+r.risk_level+' risk ('+r.risk_score+'/100). '+(r.signals||[]).slice(0,2).join('; '); } catch {} }
      return flagged;
    })()`;
    const flagged = await tab.view.webContents.executeJavaScript(applyScript, true);
    if (flagged) win.webContents.send("browser:status", { kind: "warning", message: `${flagged} link${flagged === 1 ? "" : "s"} on this page were highlighted for review.` });
  } catch (error) { console.warn("Page link check skipped:", error.message); }
  finally { tab.scanning = false; }
}

const extractEmailScript = `(() => {
  const host=location.hostname.toLowerCase(), gmail=host==='mail.google.com', outlook=['outlook.live.com','outlook.office.com','outlook.office365.com'].includes(host);
  if(!gmail&&!outlook)return {supported:false};
  const visible=(e)=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden'};
  let candidates=gmail?[...document.querySelectorAll('.a3s')]:[...document.querySelectorAll('[aria-label*="Message body"],[data-testid*="messageBody"],.ReadingPaneContents,[role="document"],article')];
  candidates=candidates.filter(visible).filter(e=>{const t=(e.innerText||'').trim();return t.length>=20&&t.length<=30000});
  const node=candidates.sort((a,b)=>(b.innerText||'').length-(a.innerText||'').length)[0];
  const selected=(window.getSelection?.().toString()||'').trim();
  const body=(selected||node?.innerText||'').trim().slice(0,20000);
  if(!body)return {supported:true,found:false};
  const scope=node||document, senderNode=document.querySelector('span.gD[email]')||document.querySelector('[data-testid*="sender"]');
  return {supported:true,found:true,subject:(document.querySelector('h2.hP')?.innerText||document.querySelector('[role="heading"][aria-level="2"]')?.innerText||'').trim().slice(0,250),sender:senderNode?.getAttribute('email')||senderNode?.getAttribute('title')||'',sender_name:(senderNode?.innerText||'').trim().slice(0,120),body,link_pairs:[...scope.querySelectorAll?.('a[href]')||[]].slice(0,60).map(a=>({href:a.href,text:(a.innerText||a.getAttribute('aria-label')||'').trim().slice(0,160)}))};
})()`;

function shellHandler(channel, callback) {
  ipcMain.handle(channel, async (event, ...args) => {
    if (!win || event.sender !== win.webContents) throw new Error("Invalid browser UI sender.");
    return callback(...args);
  });
}

shellHandler("browser:get-state", stateSnapshot);
shellHandler("browser:navigate", (address) => navigate(activeTab(), address));
shellHandler("browser:back", () => { const tab = activeTab(); if (tab?.view.webContents.canGoBack()) tab.view.webContents.goBack(); });
shellHandler("browser:forward", () => { const tab = activeTab(); if (tab?.view.webContents.canGoForward()) tab.view.webContents.goForward(); });
shellHandler("browser:reload", () => activeTab()?.view.webContents.reload());
shellHandler("browser:new-tab", () => createTab());
shellHandler("browser:select-tab", (id) => { if (tabs.has(id)) { activeId = id; updateLayout(); publishState(); } });
shellHandler("browser:close-tab", (id) => {
  const tab = tabs.get(id); if (!tab) return;
  win.contentView.removeChildView(tab.view); tab.view.webContents.close(); tabs.delete(id);
  if (!tabs.size) createTab(); else if (activeId === id) activeId = Array.from(tabs.keys()).at(-1);
  updateLayout(); publishState();
});
shellHandler("browser:set-protection", (enabled) => { protection = Boolean(enabled); if (protection) void scanPageLinks(activeTab()); publishState(); });
shellHandler("browser:set-chrome-height", (height) => { if (Number.isFinite(height) && height >= 96 && height <= 220) { chromeHeight = Math.round(height); updateLayout(); } });
shellHandler("browser:set-overlay", (visible) => {
  overlayVisible = Boolean(visible);
  updateLayout();
});
shellHandler("browser:scan-email", async () => {
  const tab = activeTab();
  if (!tab || !isMailPage(tab.url)) throw new Error("Open Gmail or Outlook and a single message first.");
  const email = await tab.view.webContents.executeJavaScript(extractEmailScript, true);
  if (!email?.found) throw new Error("I could not find an open email. Open a message and scan again.");
  const result = await scan({ mode: "email", email });
  return result;
});

function createWindow() {
  win = new BrowserWindow({
    width: 1380, height: 900, minWidth: 380, minHeight: 560,
    title: "Phishing & Spam Guard Browser", backgroundColor: "#f3f6fb",
    webPreferences: { preload: path.join(__dirname, "preload.js"), nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true },
  });
  win.loadFile(path.join(__dirname, "ui", "index.html"));
  win.on("resize", updateLayout);
  win.on("closed", () => { win = null; if (linkPoll) clearInterval(linkPoll); });
  createTab();
  linkPoll = setInterval(() => { if (protection) void scanPageLinks(activeTab()); }, 2500);
}

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on("window-all-closed", () => { if (scanner) scanner.kill(); if (process.platform !== "darwin") app.quit(); });
