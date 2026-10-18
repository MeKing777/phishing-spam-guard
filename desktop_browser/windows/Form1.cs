using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PhishingGuardBrowser;

public partial class Form1 : Form
{
    private const string HomeHost = "guard.local";
    private readonly WebView2 _shell = new() { Dock = DockStyle.Top, Height = 112 };
    private readonly Panel _pageHost = new() { Dock = DockStyle.Fill, BackColor = Color.White };
    private readonly List<BrowserTab> _tabs = [];
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> _pendingScans = new();
    private readonly object _scannerWriteLock = new();
    private readonly object _scannerStartLock = new();
    private readonly System.Windows.Forms.Timer _scanTimer = new() { Interval = 2500 };
    private CoreWebView2Environment? _environment;
    private Process? _scanner;
    private string? _activeTabId;
    private long _nextScanId;
    private int _chromeHeight = 112;
    private bool _protectionEnabled = true;
    private bool _overlayVisible;
    private bool _closing;
    private bool _initialized;
    private bool _scanTickRunning;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public Form1()
    {
        InitializeComponent();
        Text = "Phishing & Spam Guard Browser";
        StartPosition = FormStartPosition.CenterScreen;
        Width = 1380;
        Height = 900;
        MinimumSize = new Size(380, 560);
        BackColor = Color.White;
        Controls.Add(_pageHost);
        Controls.Add(_shell);
        Shown += async (_, _) => await InitializeBrowserAsync();
        Resize += (_, _) => UpdateSurface();
        DpiChanged += (_, _) => UpdateSurface();
        FormClosing += (_, _) => Shutdown();
        _scanTimer.Tick += async (_, _) => await ScanActivePageAsync();
    }

    private async Task InitializeBrowserAsync()
    {
        if (_initialized) return;
        try
        {
            var dataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PhishingSpamGuard",
                "BrowserData");
            Directory.CreateDirectory(dataFolder);
            _environment = await CoreWebView2Environment.CreateAsync(null, dataFolder);
            await _shell.EnsureCoreWebView2Async(_environment);
            _shell.CoreWebView2.Settings.IsWebMessageEnabled = true;
            _shell.CoreWebView2.Settings.IsStatusBarEnabled = false;
            _shell.CoreWebView2.Settings.IsZoomControlEnabled = true;
            _shell.CoreWebView2.SetVirtualHostNameToFolderMapping(
                HomeHost,
                Path.Combine(AppContext.BaseDirectory, "ui"),
                CoreWebView2HostResourceAccessKind.DenyCors);
            _shell.CoreWebView2.WebMessageReceived += OnShellMessageReceived;
            _shell.CoreWebView2.Navigate($"https://{HomeHost}/index.html");

            await CreateTabAsync();
            _initialized = true;
            _scanTimer.Start();
            UpdateSurface();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                "The browser could not start its Microsoft Edge WebView2 component.\n\n" +
                ex.Message + "\n\nInstall or repair the Microsoft Edge WebView2 Runtime, then start Guard Browser again.",
                "Guard Browser could not start",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Close();
        }
    }

    private async Task<BrowserTab> CreateTabAsync()
    {
        if (_environment is null) throw new InvalidOperationException("The browser engine is not ready.");

        var view = new WebView2 { Dock = DockStyle.Fill, Visible = false };
        var tab = new BrowserTab($"tab-{Guid.NewGuid():N}", view);
        _tabs.Add(tab);
        _pageHost.Controls.Add(view);

        try
        {
            await view.EnsureCoreWebView2Async(_environment);
            ConfigureTab(tab);
            _activeTabId = tab.Id;
            UpdateSurface();
            PublishState();
            return tab;
        }
        catch
        {
            _pageHost.Controls.Remove(view);
            _tabs.Remove(tab);
            view.Dispose();
            throw;
        }
    }

    private void ConfigureTab(BrowserTab tab)
    {
        var core = tab.View.CoreWebView2;
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.IsZoomControlEnabled = true;
        core.Settings.IsWebMessageEnabled = true;
        core.DocumentTitleChanged += (_, _) => PublishState();
        core.HistoryChanged += (_, _) => PublishState();
        core.SourceChanged += (_, _) =>
        {
            tab.Url = IsWebAddress(core.Source) ? core.Source : "";
            UpdateSurface();
            PublishState();
        };
        core.NavigationStarting += (_, args) =>
        {
            tab.Loading = true;
            PublishState();
            if (!IsWebAddress(args.Uri))
            {
                args.Cancel = true;
                SendStatus("error", "This browser only opens web addresses that use HTTP or HTTPS.");
                tab.Loading = false;
                PublishState();
                return;
            }

            var historyAction = tab.PendingHistoryAction;
            tab.PendingHistoryAction = 0;
            if (!_protectionEnabled) return;
            if (tab.ApprovedNavigations.Remove(args.Uri))
            {
                tab.ApprovedNavigationId = args.NavigationId;
                tab.ApprovedNavigationHost = new Uri(args.Uri).Host;
                return;
            }
            if (args.IsRedirected && tab.ApprovedNavigationId == args.NavigationId &&
                Uri.TryCreate(args.Uri, UriKind.Absolute, out var redirectUri) &&
                redirectUri.Host.Equals(tab.ApprovedNavigationHost, StringComparison.OrdinalIgnoreCase))
                return;
            args.Cancel = true;
            tab.Loading = false;
            PublishState();
            _ = CheckPageNavigationAsync(tab, args.Uri, historyAction);
        };
        core.NavigationCompleted += (_, args) =>
        {
            tab.Loading = false;
            tab.Url = IsWebAddress(core.Source) ? core.Source : "";
            UpdateSurface();
            PublishState();
            if (tab.ApprovedNavigationId == args.NavigationId)
            {
                tab.ApprovedNavigationId = null;
                tab.ApprovedNavigationHost = "";
            }
            if (!args.IsSuccess && args.WebErrorStatus is not (CoreWebView2WebErrorStatus.Unknown or CoreWebView2WebErrorStatus.OperationCanceled))
                SendStatus("error", DescribeNavigationError(args.WebErrorStatus));
            if (args.IsSuccess && IsGoogleTrafficChallenge(core.Source))
                SendStatus("warning", "Google is asking to verify unusual traffic from this network. This is Google's verification page, not a Guard phishing alert. Complete the check or try again later.");
            if (args.IsSuccess && tab.Id == _activeTabId && _protectionEnabled)
                _ = ScanPageLinksAsync(tab);
        };
        core.NewWindowRequested += (_, args) =>
        {
            args.Handled = true;
            if (IsWebAddress(args.Uri)) _ = OpenPopupInNewTabAsync(args.Uri);
        };
        core.PermissionRequested += (_, args) =>
        {
            args.State = CoreWebView2PermissionState.Deny;
            args.Handled = true;
        };
        _ = core.AddScriptToExecuteOnDocumentCreatedAsync(ObserverScript);
    }

    private async Task OpenPopupInNewTabAsync(string address)
    {
        try
        {
            var tab = await CreateTabAsync();
            await NavigateCheckedAsync(tab, address);
        }
        catch (Exception ex)
        {
            SendStatus("error", $"Could not open the new tab: {ex.Message}");
        }
    }

    private async void OnShellMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        long requestId = 0;
        try
        {
            using var document = JsonDocument.Parse(args.WebMessageAsJson);
            var message = document.RootElement;
            requestId = message.TryGetProperty("id", out var idValue) && idValue.TryGetInt64(out var parsedId) ? parsedId : 0;
            var command = message.TryGetProperty("command", out var commandValue) ? commandValue.GetString() ?? "" : "";
            var parameters = message.TryGetProperty("args", out var argsValue) && argsValue.ValueKind == JsonValueKind.Array
                ? argsValue
                : default;
            var result = await HandleCommandAsync(command, parameters);
            if (requestId > 0) Reply(requestId, result);
        }
        catch (Exception ex)
        {
            if (requestId > 0) ReplyError(requestId, ex.Message);
            else SendStatus("error", ex.Message);
        }
    }

    private async Task<object?> HandleCommandAsync(string command, JsonElement args)
    {
        var active = ActiveTab;
        switch (command)
        {
            case "getState":
                return StateSnapshot();
            case "navigate":
                await NavigateCheckedAsync(active ?? throw new InvalidOperationException("Create a browser tab first."), StringArg(args, 0));
                return true;
            case "back":
                if (active?.View.CoreWebView2.CanGoBack == true)
                {
                    active.PendingHistoryAction = -1;
                    active.View.CoreWebView2.GoBack();
                }
                return true;
            case "forward":
                if (active?.View.CoreWebView2.CanGoForward == true)
                {
                    active.PendingHistoryAction = 1;
                    active.View.CoreWebView2.GoForward();
                }
                return true;
            case "reload":
                if (active?.View.CoreWebView2 is not null)
                {
                    active.PendingHistoryAction = 2;
                    active.View.CoreWebView2.Reload();
                }
                return true;
            case "newTab":
                await CreateTabAsync();
                return true;
            case "selectTab":
                SelectTab(StringArg(args, 0));
                return true;
            case "closeTab":
                await CloseTabAsync(StringArg(args, 0));
                return true;
            case "setProtection":
                _protectionEnabled = BoolArg(args, 0);
                if (_protectionEnabled && active is not null) _ = ScanPageLinksAsync(active);
                PublishState();
                return true;
            case "setChromeHeight":
                var requestedHeight = IntArg(args, 0);
                if (requestedHeight is >= 96 and <= 360)
                {
                    _chromeHeight = requestedHeight;
                    UpdateSurface();
                }
                return true;
            case "setOverlay":
                _overlayVisible = BoolArg(args, 0);
                UpdateSurface();
                return true;
            case "scanEmail":
                return await ScanOpenEmailAsync(active ?? throw new InvalidOperationException("Create a browser tab first."));
            case "askLocalAi":
                if (active?.LastEmail is not JsonElement emailContent)
                    throw new InvalidOperationException("Open and scan an email first.");
                return await ScanAsync(new { mode = "ollama-email", email = emailContent, model = "llama3.2:3b" }, timeoutSeconds: 100);
            default:
                throw new InvalidOperationException("That browser action is not available.");
        }
    }

    private async Task NavigateCheckedAsync(BrowserTab tab, string rawAddress)
    {
        var address = NormalizeAddress(rawAddress);
        await NavigateWebAddressAsync(tab, address, directAddress: true);
    }

    private async Task CheckPageNavigationAsync(BrowserTab tab, string address, int historyAction)
    {
        if (tab.CheckingNavigation || _closing) return;
        tab.CheckingNavigation = true;
        try
        {
            if (await CheckAddressAllowedAsync(address, directAddress: false))
                ApproveAndNavigate(tab, address, historyAction);
        }
        catch (Exception ex)
        {
            SendStatus("error", $"The local safety check failed, so this address was not opened: {ex.Message}");
        }
        finally
        {
            tab.CheckingNavigation = false;
        }
    }

    private async Task NavigateWebAddressAsync(BrowserTab tab, string address, bool directAddress)
    {
        if (!await CheckAddressAllowedAsync(address, directAddress)) return;
        ApproveAndNavigate(tab, address, 0);
    }

    private async Task<bool> CheckAddressAllowedAsync(string address, bool directAddress)
    {
        if (_protectionEnabled)
        {
            var result = await ScanAsync(new { mode = "url", url = address });
            var level = StringProperty(result, "risk_level", "Review");
            var score = IntProperty(result, "risk_score", 0);
            if (level == "High" && !await ConfirmHighRiskAsync(address, result))
            {
                SendStatus("safe", "The suspicious navigation was stopped.");
                return false;
            }
            if (level == "Review")
                SendStatus("warning", $"Address check: Review ({score}/100). Check the full address before entering sensitive information.");
            if (level == "High")
                SendStatus("warning", $"You chose to open a high-risk address ({score}/100).");
        }
        else if (directAddress)
        {
            SendStatus("safe", "Protection is off. This address will open without a local URL check.");
        }
        return true;
    }

    private void ApproveAndNavigate(BrowserTab tab, string address, int historyAction)
    {
        if (tab.View.CoreWebView2 is null) throw new InvalidOperationException("The browser tab is still starting.");
        tab.ApprovedNavigations.Add(address);
        tab.Url = address;
        UpdateSurface();
        PublishState();
        if (historyAction == -1) tab.View.CoreWebView2.GoBack();
        else if (historyAction == 1) tab.View.CoreWebView2.GoForward();
        else if (historyAction == 2) tab.View.CoreWebView2.Reload();
        else tab.View.CoreWebView2.Navigate(address);
    }

    private Task<bool> ConfirmHighRiskAsync(string address, JsonElement result)
    {
        var signals = ReadStringArray(result, "signals").Take(5).ToArray();
        var detail = signals.Length == 0
            ? "The local URL checks found strong warning signs."
            : string.Join(Environment.NewLine, signals.Select(item => "• " + item));
        detail += Environment.NewLine + Environment.NewLine +
                  "These checks can make mistakes. Open this address anyway only if you recognize and trust it.";
        var choice = MessageBox.Show(
            this,
            $"The address has strong warning signs:\n\n{address}\n\n{detail}",
            "Suspicious address",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        return Task.FromResult(choice == DialogResult.Yes);
    }

    private void SelectTab(string id)
    {
        if (_tabs.Any(tab => tab.Id == id))
        {
            _activeTabId = id;
            UpdateSurface();
            PublishState();
            _ = ScanPageLinksAsync(ActiveTab);
        }
    }

    private async Task CloseTabAsync(string id)
    {
        var tab = _tabs.FirstOrDefault(item => item.Id == id);
        if (tab is null) return;
        _tabs.Remove(tab);
        _pageHost.Controls.Remove(tab.View);
        tab.View.Dispose();
        if (_tabs.Count == 0)
            await CreateTabAsync();
        else if (_activeTabId == id)
            _activeTabId = _tabs[^1].Id;
        UpdateSurface();
        PublishState();
    }

    private void UpdateSurface()
    {
        if (IsDisposed) return;
        var active = ActiveTab;
        var hasPage = active is not null && !string.IsNullOrWhiteSpace(active.Url);
        _pageHost.Visible = hasPage && !_overlayVisible;
        foreach (var tab in _tabs)
            tab.View.Visible = hasPage && !_overlayVisible && tab.Id == _activeTabId;
        var maxHeight = Math.Max(112, ClientSize.Height);
        var scale = Math.Max(1.0, DeviceDpi / 96.0);
        var chromeHeight = (int)Math.Ceiling(_chromeHeight * scale);
        _shell.Height = hasPage && !_overlayVisible ? Math.Clamp(chromeHeight, 96, maxHeight) : maxHeight;
        _shell.BringToFront();
    }

    private void PublishState()
    {
        if (_shell.CoreWebView2 is null || _closing) return;
        _shell.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new
        {
            type = "event",
            name = "state",
            value = StateSnapshot()
        }, JsonOptions));
    }

    private object StateSnapshot()
    {
        return new
        {
            protectionEnabled = _protectionEnabled,
            activeTabId = _activeTabId,
            tabs = _tabs.Select(tab =>
            {
                var core = tab.View.CoreWebView2;
                var title = core?.DocumentTitle;
                if (string.IsNullOrWhiteSpace(title))
                {
                    try { title = string.IsNullOrWhiteSpace(tab.Url) ? "New tab" : new Uri(tab.Url).Host; }
                    catch { title = "New tab"; }
                }
                return new
                {
                    id = tab.Id,
                    title,
                    url = tab.Url,
                    active = tab.Id == _activeTabId,
                    canGoBack = core?.CanGoBack ?? false,
                    canGoForward = core?.CanGoForward ?? false,
                    loading = tab.Loading,
                    mailPage = IsMailPage(tab.Url)
                };
            }).ToArray()
        };
    }

    private void SendStatus(string kind, string message)
    {
        if (_shell.CoreWebView2 is null || _closing) return;
        _shell.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new
        {
            type = "event",
            name = "status",
            value = new { kind, message }
        }, JsonOptions));
    }

    private void Reply(long id, object? result)
    {
        _shell.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(new { type = "reply", id, result }, JsonOptions));
    }

    private void ReplyError(long id, string error)
    {
        _shell.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(new { type = "reply", id, error }, JsonOptions));
    }

    private async Task ScanPageLinksAsync(BrowserTab? tab)
    {
        if (!_protectionEnabled || tab is null || tab.Id != _activeTabId ||
            string.IsNullOrWhiteSpace(tab.Url) || tab.ScanningLinks || _closing ||
            tab.View.CoreWebView2 is null)
            return;

        tab.ScanningLinks = true;
        try
        {
            var rawLinks = await tab.View.CoreWebView2.ExecuteScriptAsync(TakeLinksScript);
            using var linkDocument = JsonDocument.Parse(string.IsNullOrWhiteSpace(rawLinks) ? "[]" : rawLinks);
            if (linkDocument.RootElement.ValueKind != JsonValueKind.Array) return;
            var links = linkDocument.RootElement.EnumerateArray()
                .Select(item => item.TryGetProperty("url", out var value) ? value.GetString() : null)
                .Where(value => IsWebAddress(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(60)
                .ToArray();
            if (links.Length == 0) return;

            var results = await ScanAsync(new { mode = "links", urls = links });
            var resultJson = results.GetRawText();
            var applyScript = $$"""
                (() => {
                  const state = window.__guardLinks;
                  if (!state) return 0;
                  const results = {{resultJson}};
                  let flagged = 0;
                  for (const result of results) {
                    state.ratings.set(result.url, result);
                    if (result.risk_level === 'High' || result.risk_level === 'Review') flagged++;
                  }
                  if (!document.getElementById('__guardLinkCss')) {
                    const style = document.createElement('style');
                    style.id = '__guardLinkCss';
                    style.textContent = 'a[data-guard-risk="high"]{outline:2px solid #c43b43!important;outline-offset:2px!important;background:#fff0f0!important;border-radius:3px!important}a[data-guard-risk="review"]{outline:2px solid #b76e00!important;outline-offset:2px!important;background:#fff7e7!important;border-radius:3px!important}';
                    (document.head || document.documentElement).appendChild(style);
                  }
                  for (const a of document.querySelectorAll('a[href]')) {
                    try {
                      const result = state.ratings.get(new URL(a.href, location.href).href);
                      if (!result || !['High','Review'].includes(result.risk_level)) continue;
                      a.dataset.guardRisk = result.risk_level.toLowerCase();
                      a.title = 'Guard: ' + result.risk_level + ' risk (' + result.risk_score + '/100). ' + (result.signals || []).slice(0,2).join('; ');
                    } catch {}
                  }
                  return flagged;
                })()
                """;
            var rawFlagged = await tab.View.CoreWebView2.ExecuteScriptAsync(applyScript);
            if (int.TryParse(rawFlagged, out var flagged) && flagged > 0)
                SendStatus("warning", $"{flagged} link{(flagged == 1 ? "" : "s")} on this page show warning signs and have been highlighted.");
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Link scan skipped: " + ex.Message);
        }
        finally
        {
            tab.ScanningLinks = false;
        }
    }

    private async Task ScanActivePageAsync()
    {
        if (_scanTickRunning || !_initialized || _closing) return;
        _scanTickRunning = true;
        try
        {
            var tab = ActiveTab;
            if (tab is null || string.IsNullOrWhiteSpace(tab.Url)) return;
            if (_protectionEnabled) await ScanPageLinksAsync(tab);
            if (IsMailPage(tab.Url)) await AutoScanOpenEmailAsync(tab);
        }
        finally
        {
            _scanTickRunning = false;
        }
    }

    private async Task AutoScanOpenEmailAsync(BrowserTab tab)
    {
        if (tab.View.CoreWebView2 is null || tab.ScanningEmail || tab.Id != _activeTabId) return;
        tab.ScanningEmail = true;
        try
        {
            var email = await ExtractOpenEmailAsync(tab);
            if (!email.TryGetProperty("found", out var found) || !found.GetBoolean()) return;
            tab.LastEmail = email.Clone();
            var fingerprintSource = string.Join("\n",
                StringProperty(email, "subject"),
                StringProperty(email, "sender"),
                StringProperty(email, "body"));
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintSource)));
            if (string.Equals(fingerprint, tab.LastAutoEmailFingerprint, StringComparison.Ordinal)) return;
            tab.LastAutoEmailFingerprint = fingerprint;

            var result = await ScanAsync(new { mode = "email", email });
            var level = StringProperty(result, "risk_level", "Review");
            var score = IntProperty(result, "risk_score", 0);
            var category = StringProperty(result, "category", "Message");
            var signals = ReadStringArray(result, "signals").Take(2).ToArray();
            var detail = signals.Length == 0 ? "Open Scan email for the details." : string.Join("; ", signals);
            var kind = level == "Low" ? "safe" : "warning";
            SendStatus(kind, $"Email check: {level} risk ({score}/100) · {category}. {detail}");
        }
        catch (Exception ex)
        {
            SendStatus("error", $"The open email could not be checked locally: {ex.Message}");
        }
        finally
        {
            tab.ScanningEmail = false;
        }
    }

    private async Task<JsonElement> ScanOpenEmailAsync(BrowserTab tab)
    {
        if (!IsMailPage(tab.Url))
            throw new InvalidOperationException("Open Gmail or Outlook, then open one email to scan it.");
        var email = await ExtractOpenEmailAsync(tab);
        if (!email.TryGetProperty("found", out var found) || !found.GetBoolean())
            throw new InvalidOperationException("No open email was found. Open a message and scan again.");
        tab.LastEmail = email.Clone();
        return await ScanAsync(new { mode = "email", email });
    }

    private static async Task<JsonElement> ExtractOpenEmailAsync(BrowserTab tab)
    {
        var raw = await tab.View.CoreWebView2.ExecuteScriptAsync(ExtractEmailScript);
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(raw) ? "{}" : raw);
        return document.RootElement.Clone();
    }

    private async Task<JsonElement> ScanAsync(object request, int timeoutSeconds = 15)
    {
        EnsureScanner();
        var scanner = _scanner ?? throw new InvalidOperationException("The local Python checker did not start.");
        var id = Interlocked.Increment(ref _nextScanId);
        var completion = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingScans.TryAdd(id, completion)) throw new InvalidOperationException("Could not queue a local safety check.");

        try
        {
            var line = JsonSerializer.Serialize(new { id, request }, JsonOptions);
            lock (_scannerWriteLock)
            {
                if (scanner.HasExited) throw new InvalidOperationException("The local Python checker has stopped.");
                scanner.StandardInput.WriteLine(line);
                scanner.StandardInput.Flush();
            }
            return await completion.Task.WaitAsync(TimeSpan.FromSeconds(timeoutSeconds));
        }
        finally
        {
            _pendingScans.TryRemove(id, out _);
        }
    }

    private void EnsureScanner()
    {
        lock (_scannerStartLock)
        {
            if (_scanner is { HasExited: false }) return;
            var workerPath = Path.Combine(AppContext.BaseDirectory, "src", "browser_scan_worker.py");
            if (!File.Exists(workerPath))
                throw new FileNotFoundException("The local Python scanner is missing from the application folder.", workerPath);

            var python = FindPythonExecutable();
            var start = new ProcessStartInfo
            {
                FileName = python,
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.ArgumentList.Add("-u");
            start.ArgumentList.Add(workerPath);
            var previousPythonPath = start.Environment.TryGetValue("PYTHONPATH", out var existing) ? existing : "";
            start.Environment["PYTHONPATH"] = string.Join(Path.PathSeparator,
                new[] { AppContext.BaseDirectory, previousPythonPath }.Where(part => !string.IsNullOrWhiteSpace(part)));

            var process = new Process { StartInfo = start, EnableRaisingEvents = true };
            process.OutputDataReceived += (_, args) => HandleScannerOutput(args.Data);
            process.ErrorDataReceived += (_, args) =>
            {
                if (!string.IsNullOrWhiteSpace(args.Data)) Debug.WriteLine("Local checker: " + args.Data);
            };
            process.Exited += (_, _) => FailPendingScans(new InvalidOperationException("The local Python checker stopped."));
            if (!process.Start()) throw new InvalidOperationException("Could not start Python for local safety checks.");
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            _scanner = process;
        }
    }

    private string FindPythonExecutable()
    {
        var configured = Environment.GetEnvironmentVariable("PHISHING_GUARD_PYTHON");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured)) return configured;

        for (DirectoryInfo? folder = new(AppContext.BaseDirectory); folder is not null; folder = folder.Parent)
        {
            foreach (var environmentName in new[] { ".venv312", ".venv", "venv" })
            {
                var candidate = Path.Combine(folder.FullName, environmentName, "Scripts", "python.exe");
                if (File.Exists(candidate)) return candidate;
            }
        }
        return "python.exe";
    }

    private void HandleScannerOutput(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (!root.TryGetProperty("id", out var idElement) || !idElement.TryGetInt64(out var id)) return;
            if (!_pendingScans.TryRemove(id, out var completion)) return;
            if (root.TryGetProperty("error", out var errorElement))
                completion.TrySetException(new InvalidOperationException(errorElement.GetString() ?? "The local checker returned an error."));
            else if (root.TryGetProperty("result", out var result))
                completion.TrySetResult(result.Clone());
            else
                completion.TrySetException(new InvalidOperationException("The local checker returned an incomplete response."));
        }
        catch (JsonException)
        {
            Debug.WriteLine("Ignored a non-JSON line from the local checker.");
        }
    }

    private void FailPendingScans(Exception exception)
    {
        foreach (var entry in _pendingScans)
        {
            if (_pendingScans.TryRemove(entry.Key, out var completion))
                completion.TrySetException(exception);
        }
    }

    private void Shutdown()
    {
        _closing = true;
        _scanTimer.Stop();
        FailPendingScans(new InvalidOperationException("The browser is closing."));
        try
        {
            if (_scanner is { HasExited: false })
            {
                _scanner.StandardInput.Close();
                if (!_scanner.WaitForExit(500)) _scanner.Kill(true);
            }
        }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
    }

    private static string NormalizeAddress(string raw)
    {
        var value = (raw ?? "").Trim();
        if (value.Length == 0) throw new InvalidOperationException("Enter a website address or search term.");
        if (value.Length > 4096) throw new InvalidOperationException("The address is too long.");
        if (value.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("This browser blocks active-content and local-file addresses.");
        if ((value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
             value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) &&
            Uri.TryCreate(value, UriKind.Absolute, out var absolute))
            return absolute.AbsoluteUri;
        if (Uri.TryCreate("https://" + value, UriKind.Absolute, out var domain) &&
            domain.Host.Contains('.') && !value.Contains(' '))
            return domain.ToString();
        return "https://www.google.com/search?q=" + Uri.EscapeDataString(value);
    }

    private static bool IsWebAddress(string? address)
    {
        return Uri.TryCreate(address, UriKind.Absolute, out var uri) &&
               (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }

    private static string DescribeNavigationError(CoreWebView2WebErrorStatus status)
    {
        return status switch
        {
            CoreWebView2WebErrorStatus.HostNameNotResolved =>
                "Windows could not find this website's server address (DNS). Check that this PC is online, then check its DNS settings and try Reload.",
            CoreWebView2WebErrorStatus.Disconnected =>
                "The internet connection appears to be disconnected. Reconnect this PC, then try Reload.",
            CoreWebView2WebErrorStatus.CannotConnect =>
                "A connection to this website could not be made. Check the internet or proxy connection, then try Reload.",
            CoreWebView2WebErrorStatus.ValidProxyAuthenticationRequired =>
                "The configured proxy requires sign-in before this website can load.",
            CoreWebView2WebErrorStatus.Timeout =>
                "This website took too long to respond. Check the internet connection, then try Reload.",
            _ => $"The page could not be loaded ({status}). Check the internet connection and try Reload."
        };
    }

    private static bool IsMailPage(string? address)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri)) return false;
        var host = uri.Host.ToLowerInvariant();
        return host == "mail.google.com" ||
               host == "outlook.live.com" ||
               host == "outlook.office.com" ||
               host == "outlook.office365.com";
    }

    private static bool IsGoogleTrafficChallenge(string? address)
    {
        return Uri.TryCreate(address, UriKind.Absolute, out var uri) &&
               (uri.Host.Equals("google.com", StringComparison.OrdinalIgnoreCase) ||
                uri.Host.Equals("www.google.com", StringComparison.OrdinalIgnoreCase)) &&
               uri.AbsolutePath.StartsWith("/sorry", StringComparison.OrdinalIgnoreCase);
    }

    private BrowserTab? ActiveTab => _tabs.FirstOrDefault(tab => tab.Id == _activeTabId);

    private static string StringArg(JsonElement args, int index)
    {
        if (args.ValueKind != JsonValueKind.Array || args.GetArrayLength() <= index) return "";
        var value = args[index];
        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
    }

    private static bool BoolArg(JsonElement args, int index)
    {
        return args.ValueKind == JsonValueKind.Array &&
               args.GetArrayLength() > index &&
               args[index].ValueKind == JsonValueKind.True;
    }

    private static int IntArg(JsonElement args, int index)
    {
        return args.ValueKind == JsonValueKind.Array &&
               args.GetArrayLength() > index &&
               args[index].TryGetInt32(out var value)
            ? value
            : 0;
    }

    private static string StringProperty(JsonElement value, string name, string fallback = "")
    {
        return value.ValueKind == JsonValueKind.Object &&
               value.TryGetProperty(name, out var property) &&
               property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? fallback
            : fallback;
    }

    private static int IntProperty(JsonElement value, string name, int fallback)
    {
        return value.ValueKind == JsonValueKind.Object &&
               value.TryGetProperty(name, out var property) &&
               property.TryGetInt32(out var number)
            ? number
            : fallback;
    }

    private static IEnumerable<string> ReadStringArray(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object ||
            !value.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.Array)
            return [];
        return property.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString() ?? "")
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .ToArray();
    }

    private const string ObserverScript = """
        (() => {
          if (window.__guardLinks) return;
          const start = () => {
            if (!document.documentElement) return setTimeout(start, 50);
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
                  state.queue.set(url.href, { url: url.href });
                } catch {}
              }
            };
            collect(document.documentElement);
            new MutationObserver(records => records.forEach(record => {
              if (record.type === 'attributes') collect(record.target);
              for (const node of record.addedNodes || []) collect(node);
            })).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] });
          };
          start();
        })();
        """;

    private const string TakeLinksScript = """
        (() => {
          const state = window.__guardLinks;
          if (!state) return [];
          const links = Array.from(state.queue.values()).slice(0, 60);
          links.forEach(link => state.queue.delete(link.url));
          return links;
        })()
        """;

    private const string ExtractEmailScript = """
        (() => {
          const host = location.hostname.toLowerCase();
          const gmail = host === 'mail.google.com';
          const outlook = ['outlook.live.com','outlook.office.com','outlook.office365.com'].includes(host);
          if (!gmail && !outlook) return {supported:false};
          const visible = e => {
            const r=e.getBoundingClientRect(), s=getComputedStyle(e);
            return r.width>0 && r.height>0 && s.display!=='none' && s.visibility!=='hidden';
          };
          let candidates = gmail
            ? [...document.querySelectorAll('.a3s')]
            : [...document.querySelectorAll('[aria-label*="Message body"],[data-testid*="messageBody"],.ReadingPaneContents,[role="document"],article')];
          candidates = candidates.filter(visible).filter(e => {
            const text=(e.innerText||'').trim();
            return text.length>=20 && text.length<=30000;
          });
          const node = candidates.sort((a,b)=>(b.innerText||'').length-(a.innerText||'').length)[0];
          const selected = (window.getSelection?.().toString()||'').trim();
          const body = (selected || node?.innerText || '').trim().slice(0,20000);
          if (!body) return {supported:true,found:false};
          const scope = node || document;
          const senderNode = document.querySelector('span.gD[email]') || document.querySelector('[data-testid*="sender"]');
          return {
            supported:true,
            found:true,
            subject:(document.querySelector('h2.hP')?.innerText||document.querySelector('[role="heading"][aria-level="2"]')?.innerText||'').trim().slice(0,250),
            sender:senderNode?.getAttribute('email')||senderNode?.getAttribute('title')||'',
            sender_name:(senderNode?.innerText||'').trim().slice(0,120),
            body,
            link_pairs:[...(scope.querySelectorAll?.('a[href]')||[])].slice(0,60).map(a=>({
              href:a.href,
              text:(a.innerText||a.getAttribute('aria-label')||'').trim().slice(0,160)
            }))
          };
        })()
        """;

    private sealed class BrowserTab(string id, WebView2 view)
    {
        public string Id { get; } = id;
        public WebView2 View { get; } = view;
        public string Url { get; set; } = "";
        public bool Loading { get; set; }
        public bool CheckingNavigation { get; set; }
        public bool ScanningLinks { get; set; }
        public bool ScanningEmail { get; set; }
        public int PendingHistoryAction { get; set; }
        public ulong? ApprovedNavigationId { get; set; }
        public string ApprovedNavigationHost { get; set; } = "";
        public string LastAutoEmailFingerprint { get; set; } = "";
        public JsonElement? LastEmail { get; set; }
        public HashSet<string> ApprovedNavigations { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
