const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const puppeteer = require("puppeteer-core");

function findBrowser() {
  const candidates = [
    process.env.GUARD_BROWSER_EXE,
    path.join(process.env.ProgramFiles || "C:\\Program Files", "Google", "Chrome", "Application", "chrome.exe"),
    path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Microsoft", "Edge", "Application", "msedge.exe"),
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate));
}

async function main() {
  const executablePath = findBrowser();
  if (!executablePath) throw new Error("Install Google Chrome or Microsoft Edge, then run this launcher again.");
  const root = path.resolve(__dirname, "..");
  const extensionPath = path.join(root, "browser_extension");
  const profilePath = path.join(process.env.LOCALAPPDATA || os.homedir(), "PhishingSpamGuard", "GuardProfile");
  fs.mkdirSync(profilePath, { recursive: true });

  const browser = await puppeteer.launch({
    executablePath,
    headless: false,
    defaultViewport: null,
    userDataDir: profilePath,
    enableExtensions: [extensionPath],
    args: ["--no-first-run", "--no-default-browser-check", "https://www.google.com"],
  });

  const extensions = await browser.extensions();
  const guard = [...extensions.values()].find((item) => item.name === "Phishing & Spam Guard");
  if (!guard) {
    await browser.close();
    throw new Error("Chrome opened, but Guard did not load. Close it and run run_browser.bat again.");
  }
  console.log(`Guard is ready in ${path.basename(executablePath, ".exe")}. Close the browser window to finish.`);
  await new Promise((resolve) => browser.once("disconnected", resolve));
}

main().catch((error) => {
  console.error(`Guard Browser could not start: ${error.message}`);
  process.exitCode = 1;
});
