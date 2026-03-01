"""
Phishing URL Detector — Flask REST API
=======================================
Works both locally and on Render.com

Endpoints:
  GET  /api/health          — Health check
  GET  /api/model/info      — Model metadata
  GET  /api/features        — Feature names
  POST /api/predict         — Classify a single URL
  POST /api/predict/batch   — Classify up to 100 URLs
"""

import os
import sys
import time
import json
import logging
from datetime import datetime

from flask import Flask, request, jsonify

# ── Path setup ────────────────────────────────────────────────
# Works whether you run from /api or the project root
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.dirname(BASE_DIR)
MODEL_DIR  = os.path.join(ROOT_DIR, "model")
MODELS_DIR = os.path.join(MODEL_DIR, "saved_models")

# Add model dir to path so feature_extractor can be imported
sys.path.insert(0, MODEL_DIR)

from feature_extractor import extract_features, get_feature_names, features_to_vector

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Flask app ─────────────────────────────────────────────────
app = Flask(__name__)

# ── CORS — allow browser extension and any origin ────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/api/predict", methods=["OPTIONS"])
@app.route("/api/predict/batch", methods=["OPTIONS"])
def handle_options():
    return "", 204

# ── Model loading ─────────────────────────────────────────────
_model      = None
_model_meta = None

def load_model():
    global _model, _model_meta
    import joblib

    model_path = os.path.join(MODELS_DIR, "best_model.pkl")
    meta_path  = os.path.join(MODELS_DIR, "best_model_meta.json")

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at {model_path}\n"
            "Run: python model/train_model.py"
        )

    _model = joblib.load(model_path)
    logger.info(f"Model loaded from {model_path}")

    if os.path.exists(meta_path):
        with open(meta_path) as f:
            _model_meta = json.load(f)
        logger.info(
            f"Model: {_model_meta.get('model_name')} | "
            f"Accuracy: {_model_meta.get('accuracy', 0)*100:.2f}%"
        )

def get_model():
    if _model is None:
        load_model()
    return _model


# ── Core prediction ───────────────────────────────────────────
def predict_url(url: str) -> dict:
    url = url.strip()
    if not url:
        return {"error": "Empty URL", "status": "error"}
    if len(url) > 2048:
        return {"error": "URL too long (max 2048 chars)", "status": "error"}

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    t0 = time.time()

    features = extract_features(url)
    if features is None:
        return {"error": "Could not parse URL", "status": "error"}

    vector = features_to_vector(features)
    model  = get_model()

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        prediction   = int(model.predict([vector])[0])
        probabilities = model.predict_proba([vector])[0]

    phishing_prob = float(probabilities[1])

    # Risk level
    if phishing_prob >= 0.85:   risk = "HIGH"
    elif phishing_prob >= 0.55: risk = "MEDIUM"
    elif phishing_prob >= 0.30: risk = "LOW"
    else:                       risk = "SAFE"

    # Human-readable signals
    signals = []
    if features.get("is_suspicious_tld"):
        signals.append("Suspicious top-level domain (.tk .xyz .click etc.)")
    if features.get("has_ip"):
        signals.append("IP address used instead of a domain name")
    if features.get("num_phishing_keywords", 0) >= 2:
        signals.append(f"{features['num_phishing_keywords']} phishing keywords in URL")
    if features.get("has_login_keyword") and not features.get("is_https"):
        signals.append("Login page served over HTTP (not HTTPS)")
    if features.get("is_shortened_url"):
        signals.append("URL shortening service detected")
    if features.get("brand_in_subdomain"):
        signals.append("Brand name used in subdomain (spoofing attempt)")
    if features.get("has_at_sign"):
        signals.append("@ symbol in URL (browser redirect trick)")
    if features.get("subdomain_count", 0) >= 3:
        signals.append("Excessive subdomain depth")
    if features.get("url_length", 0) > 100:
        signals.append("Unusually long URL")
    if features.get("has_php_extension"):
        signals.append(".php page (common in phishing kits)")
    if features.get("has_prefix_suffix"):
        signals.append("Hyphen in domain name (e.g. paypal-secure.com)")

    elapsed_ms = round((time.time() - t0) * 1000, 1)

    return {
        "status":               "success",
        "url":                  url,
        "prediction":           "phishing" if prediction == 1 else "legitimate",
        "is_phishing":          bool(prediction == 1),
        "phishing_probability": round(phishing_prob * 100, 2),
        "confidence":           round(float(probabilities[prediction]) * 100, 2),
        "risk_level":           risk,
        "signals":              signals,
        "features_summary": {
            "url_length":        features.get("url_length"),
            "is_https":          bool(features.get("is_https")),
            "has_ip":            bool(features.get("has_ip")),
            "suspicious_tld":    bool(features.get("is_suspicious_tld")),
            "phishing_keywords": features.get("num_phishing_keywords"),
            "subdomain_depth":   features.get("subdomain_count"),
            "entropy":           features.get("url_entropy"),
        },
        "prediction_time_ms":   elapsed_ms,
        "timestamp":            datetime.utcnow().isoformat() + "Z",
    }


# ── Routes ────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service":  "Phishing URL Detector API",
        "version":  "2.0.0",
        "author":   "Caeser Mwania Mwathe — Maseno University CCS/00056/022",
        "status":   "online",
        "endpoints": {
            "GET  /api/health":        "Health check",
            "GET  /api/model/info":    "Model metrics",
            "GET  /api/features":      "Feature list",
            "POST /api/predict":       "Classify a URL",
            "POST /api/predict/batch": "Classify up to 100 URLs",
        },
    })


@app.route("/api/health", methods=["GET"])
def health():
    try:
        get_model()
        name = _model_meta.get("model_name", "Unknown") if _model_meta else "Loaded"
        acc  = f"{_model_meta.get('accuracy',0)*100:.2f}%" if _model_meta else "N/A"
        return jsonify({
            "status":    "healthy",
            "model":     name,
            "accuracy":  acc,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 503


@app.route("/api/model/info", methods=["GET"])
def model_info():
    try:
        get_model()
        if _model_meta:
            safe = {k: v for k, v in _model_meta.items()
                    if k not in ("feature_names", "feature_importance")}
            if "feature_importance" in _model_meta:
                safe["top_features"] = _model_meta["feature_importance"][:10]
            return jsonify(safe)
        return jsonify({"error": "No metadata available"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/features", methods=["GET"])
def features():
    return jsonify({
        "feature_count": len(get_feature_names()),
        "features":      get_feature_names(),
    })


@app.route("/api/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    try:
        result = predict_url(data["url"])
        code   = 200 if result.get("status") == "success" else 422
        logger.info(
            f"[{result.get('prediction','error').upper():10}] "
            f"{data['url'][:70]:70} | "
            f"{result.get('phishing_probability',0):.1f}% | "
            f"{result.get('prediction_time_ms')}ms"
        )
        return jsonify(result), code
    except Exception as e:
        logger.exception("Prediction error")
        return jsonify({"error": str(e), "status": "error"}), 500


@app.route("/api/predict/batch", methods=["POST"])
def predict_batch():
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get("urls"), list):
        return jsonify({"error": "Missing 'urls' list in request body"}), 400
    if len(data["urls"]) > 100:
        return jsonify({"error": "Max 100 URLs per batch"}), 400

    results       = []
    phishing_count = 0

    for url in data["urls"]:
        try:
            r = predict_url(str(url))
            results.append(r)
            if r.get("is_phishing"):
                phishing_count += 1
        except Exception as e:
            results.append({"url": url, "error": str(e), "status": "error"})

    return jsonify({
        "status":             "success",
        "total":              len(data["urls"]),
        "phishing_detected":  phishing_count,
        "legitimate_detected": len(data["urls"]) - phishing_count,
        "results":            results,
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


# ── Startup ───────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("=" * 55)
    logger.info("  PHISHING URL DETECTOR API")
    logger.info("=" * 55)

    try:
        load_model()
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)

    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
