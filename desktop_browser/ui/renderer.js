(() => {
  const api = window.guardBrowser;
  const $ = (id) => document.getElementById(id);
  const tabs = $("tabs");
  const address = $("address");
  const home = $("home");
  const notice = $("notice");
  let noticeTimer;
  let activeMailPage = false;

  function setNotice(kind, message) {
    if (!message) return;
    notice.className = `notice ${kind === "error" ? "high" : kind === "safe" ? "safe" : ""}`;
    const missingAddress = kind === "error" && /\bDNS\b|server address/i.test(message);
    $("notice-title").textContent = missingAddress ? "Can't find this website" : kind === "error" ? "Could not complete that action" : kind === "safe" ? "Check complete" : "Security notice";
    $("notice-detail").textContent = message;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => notice.classList.add("hidden"), 8500);
  }

  function renderState(state) {
    if (!state) return;
    tabs.replaceChildren();
    for (const tab of state.tabs || []) {
      const item = document.createElement("button");
      item.type = "button";
      item.className = `tab${tab.active ? " active" : ""}`;
      item.setAttribute("role", "tab");
      item.setAttribute("aria-selected", String(tab.active));
      item.title = tab.url || tab.title;
      const title = document.createElement("span");
      title.className = "tab-title";
      title.textContent = tab.loading ? `${tab.title} · Loading` : tab.title;
      const close = document.createElement("span");
      close.className = "tab-close";
      close.setAttribute("aria-label", `Close ${tab.title}`);
      close.textContent = "×";
      item.append(title, close);
      item.addEventListener("click", (event) => {
        if (event.target === close) void api.closeTab(tab.id).catch(showError);
        else void api.selectTab(tab.id).catch(showError);
      });
      tabs.append(item);
    }
    const active = (state.tabs || []).find((tab) => tab.active);
    if (document.activeElement !== address) address.value = active?.url || "";
    home.classList.toggle("hidden", Boolean(active?.url));
    const pageOpen = Boolean(active?.url);
    document.body.classList.toggle("page-open", pageOpen);
    if (pageOpen) window.scrollTo(0, 0);
    $("back").disabled = !active?.canGoBack;
    $("forward").disabled = !active?.canGoForward;
    $("reload").textContent = "↻";
    $("reload").title = "Reload";
    $("protection").checked = Boolean(state.protectionEnabled);
    activeMailPage = Boolean(active?.mailPage);
    $("scan-email").disabled = !active?.mailPage;
    $("scan-email").title = active?.mailPage ? "Scan the open message" : "Open Gmail or Outlook to scan an email";
    updateChromeHeight();
  }

  function updateChromeHeight() {
    const height = Math.ceil(document.querySelector(".chrome").getBoundingClientRect().height);
    void api.setChromeHeight(height).catch(() => {});
  }

  function showError(error) {
    setNotice("error", error?.message || String(error));
  }

  function renderEmailReport(result) {
    const level = result?.risk_level || "Review";
    const summary = $("report-summary");
    summary.className = `report-summary risk-${level.toLowerCase()}`;
    summary.replaceChildren();
    const score = document.createElement("strong");
    score.textContent = `${result?.risk_score ?? "—"}/100`;
    const label = document.createElement("span");
    label.textContent = `${level} risk · ${result?.category || "No obvious match"}`;
    summary.append(score, label);

    const meta = $("report-meta");
    meta.replaceChildren();
    if (result?.subject) {
      const subject = document.createElement("p");
      subject.textContent = `Subject: ${result.subject}`;
      meta.append(subject);
    }
    if (result?.sender || result?.sender_name) {
      const sender = document.createElement("p");
      sender.textContent = `From: ${result.sender_name ? `${result.sender_name} ` : ""}${result.sender ? `<${result.sender}>` : ""}`;
      meta.append(sender);
    }

    const list = $("report-signals");
    list.replaceChildren();
    for (const signal of result?.signals || []) {
      const li = document.createElement("li");
      li.textContent = signal;
      list.append(li);
    }
    const linkSection = $("report-link-section");
    const linkList = $("report-links");
    linkList.replaceChildren();
    for (const link of result?.urls || []) {
      const item = document.createElement("li");
      const host = document.createElement("span");
      host.textContent = link.host || link.url;
      host.title = link.url;
      const rating = document.createElement("span");
      rating.className = `link-risk ${String(link.risk_level || "").toLowerCase()}`;
      rating.textContent = `${link.risk_level} · ${link.risk_score}/100`;
      item.append(host, rating);
      linkList.append(item);
    }
    linkSection.classList.toggle("hidden", !linkList.childElementCount);
    $("ask-local-ai").disabled = false;
    $("ask-local-ai").textContent = "Ask local AI on this PC";
    $("ai-result").textContent = "";
    $("ai-result").classList.add("hidden");
    $("email-report").classList.remove("hidden");
    void api.setOverlay(true).catch(() => {});
    $("report-close").focus();
  }

  function closeEmailReport() {
    $("email-report").classList.add("hidden");
    void api.setOverlay(false).catch(() => {});
  }

  $("address-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void api.navigate(address.value).catch(showError);
    address.blur();
  });
  $("back").addEventListener("click", () => void api.back().catch(showError));
  $("forward").addEventListener("click", () => void api.forward().catch(showError));
  $("reload").addEventListener("click", () => void api.reload().catch(showError));
  $("new-tab").addEventListener("click", () => void api.newTab().catch(showError));
  $("protection").addEventListener("change", (event) => void api.setProtection(event.target.checked).catch(showError));
  $("scan-email").addEventListener("click", async () => {
    const button = $("scan-email");
    button.disabled = true;
    button.textContent = "Checking…";
    try { renderEmailReport(await api.scanEmail()); }
    catch (error) { showError(error); }
    finally { button.textContent = "Scan email"; button.disabled = !activeMailPage; }
  });
  $("ask-local-ai").addEventListener("click", async () => {
    const button = $("ask-local-ai");
    const result = $("ai-result");
    button.disabled = true;
    button.textContent = "Waiting for local AI…";
    result.textContent = "Checking with Ollama on this computer. This can take a little while.";
    result.classList.remove("hidden");
    try {
      const review = await api.askLocalAi();
      const explanation = String(review?.explanation || "The local model did not return an explanation.");
      result.textContent = "Local AI: " + (review?.risk_level || "Review") + " risk · " +
        (review?.category || "Email review") + ". " + explanation;
    } catch (error) {
      result.textContent = "Local AI could not check this email: " +
        (error?.message || String(error)) + ". Start Ollama with the llama3.2:3b model, then try again.";
      showError(error);
    } finally {
      button.disabled = false;
      button.textContent = "Ask local AI on this PC";
    }
  });
  $("notice-close").addEventListener("click", () => { clearTimeout(noticeTimer); notice.classList.add("hidden"); });
  $("report-close").addEventListener("click", closeEmailReport);
  $("email-report").addEventListener("click", (event) => { if (event.target === $("email-report")) closeEmailReport(); });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "l") { event.preventDefault(); address.focus(); address.select(); }
    if (event.key === "Escape" && !$("email-report").classList.contains("hidden")) closeEmailReport();
  });

  api.onState(renderState);
  api.onStatus((status) => setNotice(status?.kind, status?.message));
  api.onEmailResult(renderEmailReport);
  void api.getState().then(renderState).catch(showError);
  new ResizeObserver(updateChromeHeight).observe(document.querySelector(".chrome"));
})();
