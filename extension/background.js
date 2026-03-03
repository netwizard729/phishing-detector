/**
 * Background Service Worker — Phishing URL Detector v3
 * Fully fixed: proper async, auto-scan on every navigation, badge updates
 */
const DEFAULT_API = "https://phishing-detector-i0pb.onrender.com";

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
  apiUrl:       DEFAULT_API,
};

let stats = { checked: 0, phishing: 0, legitimate: 0, errors: 0 };

// Load persisted data on startup
chrome.storage.local.get(["settings", "stats"], (data) => {
  if (data.settings) SETTINGS = { ...SETTINGS, ...data.settings };
  if (data.stats)    stats    = data.stats;
  console.log("[PhishDetect] Background started. API:", SETTINGS.apiUrl);
});

function saveStats() {
  chrome.storage.local.set({ stats });
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

// ── Should we skip this URL? ──────────────────────────────────
function shouldSkip(url) {
  if (!url || typeof url !== "string") return true;
  const skip = ["chrome://","chrome-extension://","about:","file://",
                "moz-extension://","edge://","brave://","data:","javascript:"];
  if (skip.some(p => url.startsWith(p))) return true;
  if (url === "about:blank") return true;
  try {
    const h = new URL(url).hostname.toLowerCase();
    if ((SETTINGS.whitelist || []).some(d => h === d || h.endsWith("."+d))) return true;
  } catch { return true; }
  if (SETTINGS.skipHttps && url.startsWith("https://")) return true;
  return false;
}

// ── Set badge ─────────────────────────────────────────────────
function setBadge(tabId, text, color) {
  chrome.action.setBadgeText({ tabId, text: String(text) });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function setBadgeScanning(tabId) {
  setBadge(tabId, "…", "#3182ce");
}

function setBadgeFromResult(tabId, result) {
  if (!result || result.api_offline) {
    setBadge(tabId, "?", "#888888");
    return;
  }
  const risk = (result.risk_level || "SAFE").toUpperCase();
  const colors = { SAFE:"#38a169", LOW:"#d69e2e", MEDIUM:"#ed8936", HIGH:"#e53e3e" };
  const labels = { SAFE:"✓", LOW:"!", MEDIUM:"!!", HIGH:"!!!" };
  setBadge(tabId, labels[risk] || "?", colors[risk] || "#888");
}

// ── Core: call API ────────────────────────────────────────────
async function checkUrl(url) {
  if (shouldSkip(url)) return null;

  const cached = getCached(url);
  if (cached) return cached;

  const apiBase = (SETTINGS.apiUrl || DEFAULT_API).replace(/\/+$/, "");

  try {
    const res = await fetch(`${apiBase}/predict`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  AbortSignal.timeout(10000),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

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
    console.error("[PhishDetect] API error:", err.message);
    return { error: err.message, api_offline: true };
  }
}

// ── Handle navigation ─────────────────────────────────────────
async function handleNav(tabId, url) {
  if (!SETTINGS.autoScan || shouldSkip(url)) return;

  console.log("[PhishDetect] Scanning:", url);

  // Show scanning badge immediately
  setBadgeScanning(tabId);

  const result = await checkUrl(url);
  if (!result) { setBadge(tabId, "", "#888"); return; }

  // Store for popup
  chrome.storage.local.set({
    [`result_${tabId}`]: { ...result, checked_at: Date.now(), scanned_url: url }
  });

  // Update badge
  setBadgeFromResult(tabId, result);

  // Banner injection
  const risk = result.risk_level || "SAFE";
  const showWarn = (risk === "HIGH" && SETTINGS.showBanner) ||
                   (risk === "MEDIUM" && SETTINGS.alertMedium && SETTINGS.showBanner);
  if (showWarn) {
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, { type:"PHISHING_DETECTED", result })
        .catch(() => {});
    }, 900);
  }

  // Desktop notification
  if (risk === "HIGH" && SETTINGS.showNotif) {
    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icons/icon48.png",
      title:    "🚨 Phishing Site Detected!",
      message:  `${url.substring(0,70)}\nRisk: ${result.phishing_probability?.toFixed(0)}%`,
      priority: 2,
    });
  }
}

// ── Navigation events ─────────────────────────────────────────
// Every full page load
chrome.webNavigation.onCompleted.addListener((d) => {
  if (d.frameId !== 0) return;
  handleNav(d.tabId, d.url);
}, { url: [{ schemes: ["http","https"] }] });

// SPA pushState/replaceState (React, Vue, Angular, etc)
chrome.webNavigation.onHistoryStateUpdated.addListener((d) => {
  if (d.frameId !== 0 || !SETTINGS.scanOnChange) return;
  handleNav(d.tabId, d.url);
}, { url: [{ schemes: ["http","https"] }] });

// Hash changes
chrome.webNavigation.onReferenceFragmentUpdated.addListener((d) => {
  if (d.frameId !== 0 || !SETTINGS.scanOnChange) return;
  handleNav(d.tabId, d.url);
}, { url: [{ schemes: ["http","https"] }] });

// ── Tab switch: restore badge from stored result ───────────────
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.storage.local.get([`result_${tabId}`], (data) => {
    const result = data[`result_${tabId}`];
    if (result) setBadgeFromResult(tabId, result);
    else setBadge(tabId, "", "#888888");
  });
});

// ── Messages from popup / content script ─────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === "CHECK_URL") {
    checkUrl(msg.url)
      .then(r => sendResponse(r || { error:"No result", api_offline:true }))
      .catch(e => sendResponse({ error: e.message, api_offline:true }));
    return true; // keep channel open for async
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
    stats = { checked:0, phishing:0, legitimate:0, errors:0 };
    saveStats();
    sendResponse({ ok:true });
    return false;
  }

  if (msg.type === "SETTINGS_UPDATED") {
    SETTINGS = { ...SETTINGS, ...msg.settings };
    urlCache.clear();
    sendResponse({ ok:true });
    return false;
  }
});

function truncate(s, n) { return s && s.length > n ? s.slice(0,n)+"…" : (s||""); }
