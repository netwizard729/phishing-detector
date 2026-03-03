/**
 * Background Service Worker — Phishing URL Detector v4
 * Fixed: always reads API URL from storage before making any request
 */

let SETTINGS = {
  threshold:    55,
  showBanner:   true,
  showNotif:    true,
  alertMedium:  false,
  minBadgeRisk: "medium",
  autoScan:     true,
  scanOnChange: true,
  cacheDuration: 10,
  skipHttps:    false,
  whitelist:    [],
  apiUrl:       "https://phishing-detector-i0pb.onrender.com",
};

let stats        = { checked: 0, phishing: 0, legitimate: 0, errors: 0 };
let settingsLoaded = false;

// ── Load settings from storage on startup ─────────────────────
function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["settings", "stats"], (data) => {
      if (data.settings) SETTINGS = { ...SETTINGS, ...data.settings };
      if (data.stats)    stats    = data.stats;
      settingsLoaded = true;
      console.log("[PhishDetect] Settings loaded. API:", SETTINGS.apiUrl);
      resolve();
    });
  });
}

// Always load on startup
loadSettings();

function saveStats() {
  chrome.storage.local.set({ stats });
}

// ── Get API base URL — always from storage ────────────────────
function getApiBase() {
  return (SETTINGS.apiUrl || "http://localhost:5000/api").replace(/\/+$/, "");
}

// ── Cache ─────────────────────────────────────────────────────
const urlCache = new Map();

function getCached(url) {
  const hit = urlCache.get(url);
  if (!hit) return null;
  const ttl = (SETTINGS.cacheDuration || 10) * 60 * 1000;
  if (Date.now() - hit.ts > ttl) { urlCache.delete(url); return null; }
  return hit.result;
}

function setCache(url, result) {
  urlCache.set(url, { result, ts: Date.now() });
}

// ── Skip check ────────────────────────────────────────────────
function shouldSkip(url) {
  if (!url || typeof url !== "string") return true;
  const skip = ["chrome://", "chrome-extension://", "about:", "file://",
                "moz-extension://", "edge://", "brave://", "data:", "javascript:"];
  if (skip.some(p => url.startsWith(p))) return true;
  if (url === "about:blank") return true;
  try {
    const h = new URL(url).hostname.toLowerCase();
    if ((SETTINGS.whitelist || []).some(d => h === d || h.endsWith("." + d))) return true;
  } catch { return true; }
  if (SETTINGS.skipHttps && url.startsWith("https://")) return true;
  return false;
}

// ── Badge helpers ─────────────────────────────────────────────
function setBadge(tabId, text, color) {
  chrome.action.setBadgeText({ tabId, text: String(text) });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}
function setBadgeScanning(tabId) { setBadge(tabId, "…", "#3182ce"); }
function setBadgeFromResult(tabId, result) {
  if (!result || result.api_offline) { setBadge(tabId, "?", "#888888"); return; }
  const risk   = (result.risk_level || "SAFE").toUpperCase();
  const colors = { SAFE:"#38a169", LOW:"#d69e2e", MEDIUM:"#ed8936", HIGH:"#e53e3e" };
  const labels = { SAFE:"✓", LOW:"!", MEDIUM:"!!", HIGH:"!!!" };
  setBadge(tabId, labels[risk] || "?", colors[risk] || "#888");
}

// ── Core: call API ────────────────────────────────────────────
async function checkUrl(url) {
  if (shouldSkip(url)) return null;

  const cached = getCached(url);
  if (cached) return cached;

  // Always re-read from storage to get latest saved API URL
  await new Promise(resolve => {
    chrome.storage.local.get(["settings"], (data) => {
      if (data.settings) SETTINGS = { ...SETTINGS, ...data.settings };
      resolve();
    });
  });

  const apiBase = getApiBase();
  console.log("[PhishDetect] Calling API:", apiBase, "for URL:", url);

  try {
    const res = await fetch(`${apiBase}/predict`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 100)}`);
    }

    const result = await res.json();

    // Apply user threshold
    const thr  = SETTINGS.threshold || 55;
    const prob = result.phishing_probability || 0;
    result.is_phishing = prob >= thr;
    if      (prob < thr)       result.risk_level = "SAFE";
    else if (prob < thr + 15)  result.risk_level = "LOW";
    else if (prob < thr + 30)  result.risk_level = "MEDIUM";
    else                       result.risk_level = "HIGH";

    setCache(url, result);
    stats.checked++;
    result.is_phishing ? stats.phishing++ : stats.legitimate++;
    saveStats();

    return result;

  } catch (err) {
    stats.errors++;
    saveStats();
    console.error("[PhishDetect] API error:", err.message, "| API URL was:", apiBase);
    return { error: err.message, api_offline: true, api_url_used: apiBase };
  }
}

// ── Handle navigation ─────────────────────────────────────────
async function handleNav(tabId, url) {
  if (!SETTINGS.autoScan || shouldSkip(url)) return;

  setBadgeScanning(tabId);
  const result = await checkUrl(url);
  if (!result) { setBadge(tabId, "", "#888888"); return; }

  chrome.storage.local.set({
    [`result_${tabId}`]: { ...result, checked_at: Date.now(), scanned_url: url }
  });

  setBadgeFromResult(tabId, result);

  const risk = result.risk_level || "SAFE";
  const showWarn = (risk === "HIGH" && SETTINGS.showBanner) ||
                   (risk === "MEDIUM" && SETTINGS.alertMedium && SETTINGS.showBanner);
  if (showWarn) {
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, { type: "PHISHING_DETECTED", result })
        .catch(() => {});
    }, 900);
  }

  if (risk === "HIGH" && SETTINGS.showNotif) {
    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icons/icon48.png",
      title:    "🚨 Phishing Site Detected!",
      message:  `${url.substring(0, 70)}\nRisk: ${result.phishing_probability?.toFixed(0)}%`,
      priority: 2,
    });
  }
}

// ── Navigation listeners ──────────────────────────────────────
chrome.webNavigation.onCompleted.addListener((d) => {
  if (d.frameId !== 0) return;
  handleNav(d.tabId, d.url);
}, { url: [{ schemes: ["http", "https"] }] });

chrome.webNavigation.onHistoryStateUpdated.addListener((d) => {
  if (d.frameId !== 0 || !SETTINGS.scanOnChange) return;
  handleNav(d.tabId, d.url);
}, { url: [{ schemes: ["http", "https"] }] });

chrome.webNavigation.onReferenceFragmentUpdated.addListener((d) => {
  if (d.frameId !== 0 || !SETTINGS.scanOnChange) return;
  handleNav(d.tabId, d.url);
}, { url: [{ schemes: ["http", "https"] }] });

// ── Restore badge when switching tabs ─────────────────────────
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.storage.local.get([`result_${tabId}`], (data) => {
    const result = data[`result_${tabId}`];
    if (result) setBadgeFromResult(tabId, result);
    else setBadge(tabId, "", "#888888");
  });
});

// ── Message handler ───────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === "CHECK_URL") {
    checkUrl(msg.url)
      .then(r => sendResponse(r || { error: "No result", api_offline: true }))
      .catch(e => sendResponse({ error: e.message, api_offline: true }));
    return true;
  }

  if (msg.type === "GET_RESULT") {
    chrome.storage.local.get([`result_${msg.tabId}`], (data) => {
      sendResponse(data[`result_${msg.tabId}`] || null);
    });
    return true;
  }

  if (msg.type === "GET_STATS") {
    sendResponse({ ...stats });
    return false;
  }

  if (msg.type === "RESET_STATS") {
    stats = { checked: 0, phishing: 0, legitimate: 0, errors: 0 };
    saveStats();
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === "SETTINGS_UPDATED") {
    SETTINGS = { ...SETTINGS, ...msg.settings };
    urlCache.clear();
    console.log("[PhishDetect] Settings updated. New API:", SETTINGS.apiUrl);
    sendResponse({ ok: true });
    return false;
  }
});
