let currentTabId  = null;
let currentTabUrl = "";

// ── Render result ─────────────────────────────────────────────
function render(result) {
  const el = document.getElementById("main");

  if (!result) {
    el.innerHTML = `<div class="notice warn"><strong>No result yet.</strong>Click 🔄 to scan this page.</div>`;
    return;
  }

  if (result.api_offline || (result.error && !result.prediction)) {
    el.innerHTML = `
      <div class="notice warn">
        <strong>⚠️ API not reachable</strong>
        Make sure the Flask server is running:<br>
        <code>bash run.sh api</code><br>
        Then click 🔄 to retry.
      </div>`;
    return;
  }

  const risk      = (result.risk_level || "UNKNOWN").toUpperCase();
  const riskLow   = risk.toLowerCase();
  const icons     = { SAFE:"✅", LOW:"⚠️", MEDIUM:"🔶", HIGH:"🚨", UNKNOWN:"❓" };
  const icon      = icons[risk] || "❓";
  const prob      = Number(result.phishing_probability) || 0;
  const fillClass = { safe:"fill-safe", low:"fill-low", medium:"fill-medium", high:"fill-high" }[riskLow] || "fill-safe";
  const signals   = Array.isArray(result.signals) ? result.signals : [];

  const sigHtml = signals.length
    ? signals.map(s => `<div class="sig-item"><span class="sig-dot">●</span>${s}</div>`).join("")
    : `<div class="sig-item"><span class="sig-ok">✓</span> No suspicious signals detected</div>`;

  const rawUrl  = result.url || result.scanned_url || currentTabUrl || "";
  const dispUrl = rawUrl.length > 52 ? rawUrl.slice(0, 52) + "…" : rawUrl;

  el.innerHTML = `
    <div class="card">
      <div class="banner ${riskLow}">
        <div class="b-icon">${icon}</div>
        <div>
          <div class="b-label">${risk} RISK</div>
          <div class="b-sub">
            ${(result.prediction || "unknown").toUpperCase()}
            &nbsp;·&nbsp; ${prob.toFixed(1)}% phishing probability
            ${result.prediction_time_ms ? `&nbsp;·&nbsp; ${result.prediction_time_ms}ms` : ""}
          </div>
        </div>
      </div>
      <div class="prob">
        <div class="prob-row">
          <span>Phishing Probability</span>
          <span class="prob-val">${prob.toFixed(1)}%</span>
        </div>
        <div class="track">
          <div class="fill ${fillClass}" style="width:${Math.min(prob, 100)}%"></div>
        </div>
      </div>
    </div>
    <div class="url-box"><strong>URL Analysed</strong>${dispUrl}</div>
    <div class="signals">
      <div class="sig-title">Detection Signals</div>
      ${sigHtml}
    </div>`;
}

// ── Scan a URL ────────────────────────────────────────────────
function scanUrl(url, label) {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:")) {
    document.getElementById("main").innerHTML =
      `<div class="notice warn"><strong>Cannot scan this page.</strong>Navigate to a website first, then open the extension.</div>`;
    return;
  }

  showScan(label || "Scanning…");
  document.getElementById("main").innerHTML =
    `<div class="loader"><div class="spinner"></div>${label || "Scanning…"}</div>`;

  chrome.runtime.sendMessage({ type: "CHECK_URL", url }, (result) => {
    hideScan();
    if (chrome.runtime.lastError) {
      document.getElementById("main").innerHTML =
        `<div class="notice error"><strong>Extension error</strong>${chrome.runtime.lastError.message}</div>`;
      return;
    }
    render(result);
    loadStats();
  });
}

// ── Init ──────────────────────────────────────────────────────
async function init() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab  = tabs[0];
    if (!tab) return;

    currentTabId  = tab.id;
    currentTabUrl = tab.url || "";

    // Pre-fill input with current page URL
    document.getElementById("urlInput").value = currentTabUrl;

    // Check for cached result first
    chrome.runtime.sendMessage({ type: "GET_RESULT", tabId: tab.id }, (cached) => {
      if (cached && cached.prediction && !cached.api_offline) {
        render(cached);
      } else {
        scanUrl(currentTabUrl, "Scanning current page…");
      }
    });

  } catch (e) {
    document.getElementById("main").innerHTML =
      `<div class="notice error"><strong>Error</strong>${e.message}</div>`;
  }
}

// ── Re-scan ───────────────────────────────────────────────────
function rescan() {
  const url = document.getElementById("urlInput").value.trim() || currentTabUrl;
  if (url) scanUrl(url, "Re-scanning…");
}

// ── Manual check ──────────────────────────────────────────────
function checkManual() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) return;
  const btn = document.getElementById("checkBtn");
  btn.disabled = true;
  btn.textContent = "…";
  scanUrl(url, "Checking URL…");
  setTimeout(() => { btn.disabled = false; btn.textContent = "Check"; }, 3000);
}

// ── Settings ──────────────────────────────────────────────────
function openSettings() {
  chrome.tabs.create({ url: chrome.runtime.getURL("settings.html") });
  window.close();
}

// ── Scan bar ──────────────────────────────────────────────────
function showScan(msg) {
  document.getElementById("scanText").textContent = msg;
  document.getElementById("scanBar").classList.remove("hidden");
}
function hideScan() {
  document.getElementById("scanBar").classList.add("hidden");
}

// ── Stats ─────────────────────────────────────────────────────
function loadStats() {
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (s) => {
    if (!s) return;
    document.getElementById("sTotal").textContent = s.checked    || 0;
    document.getElementById("sPhish").textContent = s.phishing   || 0;
    document.getElementById("sSafe").textContent  = s.legitimate || 0;
  });
}

// ── API health ────────────────────────────────────────────────
async function checkApi() {
  const lbl = document.getElementById("apiLabel");
  try {
    const stored = await chrome.storage.local.get(["settings"]);
    const base   = stored.settings?.apiUrl || "https://phishing-url-detector.onrender.com/api";
    const res    = await fetch(`${base}/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const d = await res.json();
      lbl.textContent = `API online · ${d.accuracy || ""}`;
      lbl.style.color = "#9ae6b4";
    } else throw new Error();
  } catch {
    lbl.textContent = "API offline";
    lbl.style.color = "#fc8181";
  }
}

// ── Wire up event listeners once DOM is ready ─────────────────
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("checkBtn").addEventListener("click", checkManual);
  document.getElementById("urlInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") checkManual();
  });
  document.getElementById("rescanBtn").addEventListener("click", rescan);
  document.getElementById("settingsBtn").addEventListener("click", openSettings);
  document.getElementById("settingsFooterBtn").addEventListener("click", openSettings);

  init();
  loadStats();
  checkApi();
});
