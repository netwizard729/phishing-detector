const DEFAULTS = {
  threshold:    55,
  showBanner:   true,
  showNotif:    true,
  alertMedium:  false,
  minBadgeRisk: "medium",
  autoScan:     true,
  scanOnChange: true,
  cacheDuration: 10,
  skipHttps:    false,
  saveHistory:  false,
  sendStats:    false,
  whitelist:    [],
  apiUrl:       "https://phishing-url-detector.onrender.com/api",
};

let whitelist = [];

// ── Load settings from storage ────────────────────────────────
function loadSettings() {
  chrome.storage.local.get(["settings"], (result) => {
    const s = result.settings ? { ...DEFAULTS, ...result.settings } : DEFAULTS;
    applyToUI(s);
  });
}

function applyToUI(s) {
  document.getElementById("thresholdSlider").value = s.threshold;
  updateThreshold(s.threshold);
  document.getElementById("showBanner").checked    = s.showBanner;
  document.getElementById("showNotif").checked     = s.showNotif;
  document.getElementById("alertMedium").checked   = s.alertMedium;
  document.getElementById("minBadgeRisk").value    = s.minBadgeRisk;
  document.getElementById("autoScan").checked      = s.autoScan;
  document.getElementById("scanOnChange").checked  = s.scanOnChange;
  document.getElementById("cacheDuration").value   = s.cacheDuration;
  document.getElementById("skipHttps").checked     = s.skipHttps;
  document.getElementById("saveHistory").checked   = s.saveHistory;
  document.getElementById("sendStats").checked     = s.sendStats;
  document.getElementById("apiUrl").value          = s.apiUrl || DEFAULTS.apiUrl;
  whitelist = s.whitelist || [];
  renderWhitelist();
}

function collectSettings() {
  return {
    threshold:     parseInt(document.getElementById("thresholdSlider").value),
    showBanner:    document.getElementById("showBanner").checked,
    showNotif:     document.getElementById("showNotif").checked,
    alertMedium:   document.getElementById("alertMedium").checked,
    minBadgeRisk:  document.getElementById("minBadgeRisk").value,
    autoScan:      document.getElementById("autoScan").checked,
    scanOnChange:  document.getElementById("scanOnChange").checked,
    cacheDuration: parseInt(document.getElementById("cacheDuration").value),
    skipHttps:     document.getElementById("skipHttps").checked,
    saveHistory:   document.getElementById("saveHistory").checked,
    sendStats:     document.getElementById("sendStats").checked,
    whitelist:     [...whitelist],
    apiUrl:        document.getElementById("apiUrl").value.trim() || DEFAULTS.apiUrl,
  };
}

// ── Save ──────────────────────────────────────────────────────
function saveSettings() {
  const s = collectSettings();
  chrome.storage.local.set({ settings: s }, () => {
    chrome.runtime.sendMessage({ type: "SETTINGS_UPDATED", settings: s });
    const msg = document.getElementById("saveMsg");
    msg.textContent = "✓ Settings saved!";
    msg.className = "save-msg saved";
    setTimeout(() => {
      msg.textContent = "Changes will apply immediately after saving.";
      msg.className = "save-msg";
    }, 2500);
  });
}

// ── Reset ─────────────────────────────────────────────────────
function resetDefaults() {
  if (confirm("Reset all settings to defaults?")) applyToUI(DEFAULTS);
}

// ── Threshold slider ──────────────────────────────────────────
function updateThreshold(val) {
  val = parseInt(val);
  document.getElementById("thresholdVal").textContent = val + "%";
  const medium = Math.min(val + 15, 95);
  const high   = Math.min(val + 30, 100);
  document.getElementById("safeRange").textContent = `0–${val - 1}%`;
  document.getElementById("lowRange").textContent  = `${val}–${medium - 1}%`;
  document.getElementById("medRange").textContent  = `${medium}–${high - 1}%`;
  document.getElementById("highRange").textContent = `${high}–100%`;
}

// ── Whitelist ─────────────────────────────────────────────────
function addWhitelist() {
  const input = document.getElementById("wlInput");
  let val = input.value.trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!val || whitelist.includes(val)) { input.value = ""; return; }
  whitelist.push(val);
  input.value = "";
  renderWhitelist();
}

function removeWhitelist(domain) {
  whitelist = whitelist.filter(d => d !== domain);
  renderWhitelist();
}

function renderWhitelist() {
  const container = document.getElementById("wlTags");
  if (!whitelist.length) {
    container.innerHTML = '<span class="wl-empty">No trusted domains added yet.</span>';
    return;
  }
  container.innerHTML = whitelist.map(d => `
    <div class="wl-tag">
      ${d}
      <button class="wl-remove" data-domain="${d}" title="Remove">×</button>
    </div>`).join("");

  // Attach remove handlers
  container.querySelectorAll(".wl-remove").forEach(btn => {
    btn.addEventListener("click", () => removeWhitelist(btn.dataset.domain));
  });
}

// ── Test API ──────────────────────────────────────────────────
async function testApi() {
  const url    = document.getElementById("apiUrl").value.trim();
  const status = document.getElementById("apiStatus");
  status.textContent = "⏳ Testing…";
  status.style.color = "#718096";
  try {
    const res  = await fetch(`${url}/health`, { signal: AbortSignal.timeout(4000) });
    const data = await res.json();
    if (res.ok) {
      status.textContent = `✅ Connected — Model: ${data.model} · Accuracy: ${data.accuracy}`;
      status.style.color = "#38a169";
    } else throw new Error();
  } catch {
    status.textContent = "❌ Cannot connect. Is bash run.sh api running?";
    status.style.color = "#e53e3e";
  }
}

// ── Wire up events ────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("thresholdSlider").addEventListener("input", (e) => updateThreshold(e.target.value));
  document.getElementById("wlInput").addEventListener("keydown", (e) => { if (e.key === "Enter") addWhitelist(); });
  document.getElementById("wlAddBtn").addEventListener("click", addWhitelist);
  document.getElementById("testApiBtn").addEventListener("click", testApi);
  document.getElementById("saveBtn").addEventListener("click", saveSettings);
  document.getElementById("resetBtn").addEventListener("click", resetDefaults);
  loadSettings();
});
