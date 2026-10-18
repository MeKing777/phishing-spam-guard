const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("guardBrowser", {
  getState: () => ipcRenderer.invoke("browser:get-state"),
  navigate: (address) => ipcRenderer.invoke("browser:navigate", address),
  back: () => ipcRenderer.invoke("browser:back"),
  forward: () => ipcRenderer.invoke("browser:forward"),
  reload: () => ipcRenderer.invoke("browser:reload"),
  newTab: () => ipcRenderer.invoke("browser:new-tab"),
  selectTab: (id) => ipcRenderer.invoke("browser:select-tab", id),
  closeTab: (id) => ipcRenderer.invoke("browser:close-tab", id),
  scanEmail: () => ipcRenderer.invoke("browser:scan-email"),
  setProtection: (enabled) => ipcRenderer.invoke("browser:set-protection", enabled),
  setChromeHeight: (height) => ipcRenderer.invoke("browser:set-chrome-height", height),
  setOverlay: (visible) => ipcRenderer.invoke("browser:set-overlay", visible),
  onState: (callback) => ipcRenderer.on("browser:state", (_event, value) => callback(value)),
  onStatus: (callback) => ipcRenderer.on("browser:status", (_event, value) => callback(value)),
  onEmailResult: (callback) => ipcRenderer.on("browser:email-result", (_event, value) => callback(value)),
});
