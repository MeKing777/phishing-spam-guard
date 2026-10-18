(() => {
  const pending = new Map();
  let nextId = 0;
  const listeners = { state: null, status: null, emailResult: null };

  function call(command, ...args) {
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      try {
        window.chrome.webview.postMessage({ id, command, args });
      } catch (error) {
        pending.delete(id);
        reject(error);
      }
    });
  }

  window.chrome.webview.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || typeof message !== "object") return;
    if (message.type === "reply") {
      const task = pending.get(message.id);
      if (!task) return;
      pending.delete(message.id);
      if (message.error) task.reject(new Error(message.error));
      else task.resolve(message.result);
      return;
    }
    if (message.type !== "event") return;
    const callback = message.name === "state" ? listeners.state
      : message.name === "status" ? listeners.status
      : message.name === "email-result" ? listeners.emailResult
      : null;
    if (callback) callback(message.value);
  });

  window.guardBrowser = Object.freeze({
    getState: () => call("getState"),
    navigate: (address) => call("navigate", address),
    back: () => call("back"),
    forward: () => call("forward"),
    reload: () => call("reload"),
    newTab: () => call("newTab"),
    selectTab: (id) => call("selectTab", id),
    closeTab: (id) => call("closeTab", id),
    scanEmail: () => call("scanEmail"),
    askLocalAi: () => call("askLocalAi"),
    setProtection: (enabled) => call("setProtection", enabled),
    setChromeHeight: (height) => call("setChromeHeight", height),
    setOverlay: (visible) => call("setOverlay", visible),
    onState: (callback) => { listeners.state = callback; },
    onStatus: (callback) => { listeners.status = callback; },
    onEmailResult: (callback) => { listeners.emailResult = callback; },
  });
})();
