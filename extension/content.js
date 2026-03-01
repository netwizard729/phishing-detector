/**
 * Content Script — Phishing URL Detector v3
 * - Shows warning banner on phishing pages
 * - Watches for URL changes in SPAs (React/Vue/Angular)
 *   and reports them to the background worker
 */
(function () {
  "use strict";

  let bannerShown = false;
  let lastUrl     = location.href;

  // ── Listen for warning from background ───────────────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "PHISHING_DETECTED" && !bannerShown) {
      showBanner(msg.result);
    }
  });

  // ── SPA URL watcher (MutationObserver on title changes) ──────
  // This fires when React/Vue/Angular updates the page without reload
  const observer = new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      // Remove old banner so it re-evaluates new page
      removeBanner();
      // The background already listens to webNavigation.onHistoryStateUpdated
      // but some SPAs need this extra nudge
      chrome.runtime.sendMessage({ type:"CHECK_URL", url: location.href })
        .catch(() => {});
    }
  });

  observer.observe(document, { subtree:true, childList:true });

  // ── Warning Banner ────────────────────────────────────────────
  function showBanner(result) {
    bannerShown = true;
    const prob    = result.phishing_probability || 0;
    const signals = (result.signals || []).slice(0, 2).join(" · ") || "Phishing characteristics detected";

    const banner = document.createElement("div");
    banner.id = "__phishdetect__";
    banner.style.cssText = [
      "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
      "background:linear-gradient(135deg,#c53030,#e53e3e)",
      "color:white", "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
      "font-size:14px", "padding:12px 20px",
      "display:flex", "align-items:center", "justify-content:space-between",
      "gap:12px", "box-shadow:0 4px 20px rgba(0,0,0,.4)",
    ].join("!important;") + "!important";

    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;flex:1">
        <span style="font-size:26px">🚨</span>
        <div>
          <div style="font-weight:800;font-size:15px">
            PHISHING SITE DETECTED — ${prob.toFixed(0)}% Risk
          </div>
          <div style="font-size:11px;opacity:.9;margin-top:2px">${signals}</div>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-shrink:0">
        <button id="__phish_back__" style="
          background:rgba(255,255,255,.2);border:1.5px solid rgba(255,255,255,.5);
          color:white;padding:7px 16px;border-radius:6px;cursor:pointer;
          font-size:13px;font-weight:700">← Go Back</button>
        <button id="__phish_dismiss__" style="
          background:transparent;border:none;color:rgba(255,255,255,.7);
          cursor:pointer;font-size:20px;padding:2px 8px">✕</button>
      </div>`;

    // Spacer to push page content down
    const spacer = document.createElement("div");
    spacer.id = "__phishdetect_sp__";
    spacer.style.cssText = "height:60px!important;width:100%!important;display:block!important";

    document.body.insertBefore(spacer, document.body.firstChild);
    document.body.insertBefore(banner, document.body.firstChild);

    document.getElementById("__phish_back__").onclick    = () => history.back();
    document.getElementById("__phish_dismiss__").onclick = () => removeBanner();
  }

  function removeBanner() {
    document.getElementById("__phishdetect__")?.remove();
    document.getElementById("__phishdetect_sp__")?.remove();
    bannerShown = false;
  }
})();
