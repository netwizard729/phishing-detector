"""
Phishing URL Detector — Flask REST API
=======================================
Endpoints:
  POST /api/predict       — Classify a single URL
  POST /api/predict/batch — Classify multiple URLs
  GET  /api/health        — Health check
  GET  /api/model/info    — Model metadata
  GET  /api/features      — Feature names list

Run: python app.py
"""

import os
import sys
import time
import json
import logging
from datetime import datetime

from flask import Flask, request, jsonify

# ── Path setup ─────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(BASE_DIR, "..", "model")
MODELS_DIR = os.path.join(MODEL_DIR, "saved_models")
sys.path.insert(0, MODEL_DIR)

from feature_extractor import extract_features, get_feature_names, features_to_vector

# ── Logging ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── App Init ───────────────────────────────────────────────────
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── Model Loader ───────────────────────────────────────────────
_model = None
_model_meta = None

def load_model():
    global _model, _model_meta
    import joblib

    model_path = os.path.join(MODELS_DIR, "best_model.pkl")
    meta_path  = os.path.join(MODELS_DIR, "best_model_meta.json")

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at {model_path}\n"
            "Please run: python model/train_model.py"
        )

    _model = joblib.load(model_path)
    logger.info(f"Model loaded: {model_path}")

    if os.path.exists(meta_path):
        with open(meta_path) as f:
            _model_meta = json.load(f)
        logger.info(f"Model: {_model_meta.get('model_name')} | "
                    f"Accuracy: {_model_meta.get('accuracy', 0)*100:.2f}%")

    return _model


def get_model():
    if _model is None:
        load_model()
    return _model


def predict_url(url: str) -> dict:
    """Run full prediction pipeline on a single URL."""
    t0 = time.time()

    # 1. Validate
    url = url.strip()
    if not url:
        return {"error": "Empty URL provided", "status": "error"}

    if len(url) > 2048:
        return {"error": "URL too long (max 2048 chars)", "status": "error"}

    # Prepend scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # 2. Extract features
    features = extract_features(url)
    if features is None:
        return {"error": "Failed to parse URL", "status": "error"}

    feature_vector = features_to_vector(features)

    # 3. Predict
    model = get_model()
    prediction = int(model.predict([feature_vector])[0])
    probability = float(model.predict_proba([feature_vector])[0][prediction])
    phishing_prob = float(model.predict_proba([feature_vector])[0][1])

    # 4. Risk classification
    if phishing_prob >= 0.85:
        risk_level = "HIGH"
        risk_color = "red"
    elif phishing_prob >= 0.55:
        risk_level = "MEDIUM"
        risk_color = "orange"
    elif phishing_prob >= 0.30:
        risk_level = "LOW"
        risk_color = "yellow"
    else:
        risk_level = "SAFE"
        risk_color = "green"

    # 5. Key signals for explanation
    signals = []
    if features.get("is_suspicious_tld"):
        signals.append("Suspicious top-level domain")
    if features.get("has_ip"):
        signals.append("IP address used instead of domain name")
    if features.get("num_phishing_keywords", 0) >= 2:
        signals.append(f"{features['num_phishing_keywords']} phishing keywords detected")
    if features.get("has_login_keyword") and not features.get("is_https"):
        signals.append("Login page without HTTPS")
    if features.get("is_shortened_url"):
        signals.append("URL shortening service detected")
    if features.get("brand_in_subdomain"):
        signals.append("Brand name used in subdomain (spoofing)")
    if features.get("has_at_sign"):
        signals.append("@ symbol in URL (redirect trick)")
    if features.get("subdomain_count", 0) >= 3:
        signals.append("Excessive subdomain nesting")
    if features.get("url_length", 0) > 100:
        signals.append("Unusually long URL")
    if not features.get("is_https") and prediction == 0:
        pass  # Don't flag legit HTTP sites as warning
    if features.get("has_php_extension"):
        signals.append(".php extension in phishing-heavy path")

    elapsed_ms = round((time.time() - t0) * 1000, 1)

    return {
        "status": "success",
        "url": url,
        "prediction": "phishing" if prediction == 1 else "legitimate",
        "is_phishing": bool(prediction == 1),
        "phishing_probability": round(phishing_prob * 100, 2),
        "confidence": round(probability * 100, 2),
        "risk_level": risk_level,
        "risk_color": risk_color,
        "signals": signals,
        "features_summary": {
            "url_length": features.get("url_length"),
            "is_https": bool(features.get("is_https")),
            "has_ip": bool(features.get("has_ip")),
            "suspicious_tld": bool(features.get("is_suspicious_tld")),
            "phishing_keywords": features.get("num_phishing_keywords"),
            "subdomain_depth": features.get("subdomain_count"),
            "entropy": features.get("url_entropy"),
        },
        "prediction_time_ms": elapsed_ms,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

@app.after_request
def add_cors_headers(response):
    """Allow browser extension and local dev to call the API."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    try:
        model = get_model()
        model_name = _model_meta.get("model_name", "Unknown") if _model_meta else "Loaded"
        return jsonify({
            "status": "healthy",
            "model": model_name,
            "accuracy": f"{_model_meta.get('accuracy', 0)*100:.2f}%" if _model_meta else "N/A",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 503


@app.route("/api/model/info", methods=["GET"])
def model_info():
    """Return model metadata and performance metrics."""
    try:
        get_model()
        if _model_meta:
            safe_meta = {k: v for k, v in _model_meta.items()
                         if k not in ("feature_names", "feature_importance")}
            # Include top features
            if "feature_importance" in _model_meta:
                safe_meta["top_features"] = _model_meta["feature_importance"][:10]
            return jsonify(safe_meta)
        return jsonify({"error": "No model metadata available"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/features", methods=["GET"])
def features():
    """Return the list of extracted feature names."""
    return jsonify({
        "feature_count": len(get_feature_names()),
        "features": get_feature_names(),
    })


@app.route("/api/predict", methods=["POST", "OPTIONS"])
def predict():
    """
    Classify a single URL.

    Request body (JSON):
        { "url": "https://example.com" }

    Response:
        {
          "prediction": "legitimate" | "phishing",
          "is_phishing": true | false,
          "phishing_probability": 87.3,
          "risk_level": "HIGH" | "MEDIUM" | "LOW" | "SAFE",
          "signals": ["Suspicious TLD", ...],
          ...
        }
    """
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' field in request body"}), 400

    try:
        result = predict_url(url)
        status_code = 200 if result.get("status") == "success" else 422
        logger.info(f"[{result.get('prediction', 'error').upper()}] {url[:80]} "
                    f"| {result.get('phishing_probability', 0):.1f}% | {result.get('prediction_time_ms')}ms")
        return jsonify(result), status_code
    except Exception as e:
        logger.exception(f"Prediction error for URL: {url}")
        return jsonify({"error": f"Internal error: {str(e)}", "status": "error"}), 500


@app.route("/api/predict/batch", methods=["POST", "OPTIONS"])
def predict_batch():
    """
    Classify multiple URLs at once.

    Request body (JSON):
        { "urls": ["https://url1.com", "http://evil.tk/login.php", ...] }

    Max: 100 URLs per request.
    """
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    urls = data.get("urls", [])
    if not urls or not isinstance(urls, list):
        return jsonify({"error": "Missing or invalid 'urls' list"}), 400

    if len(urls) > 100:
        return jsonify({"error": "Maximum 100 URLs per batch request"}), 400

    results = []
    phishing_count = 0

    for url in urls:
        try:
            result = predict_url(str(url))
            results.append(result)
            if result.get("is_phishing"):
                phishing_count += 1
        except Exception as e:
            results.append({"url": url, "error": str(e), "status": "error"})

    return jsonify({
        "status": "success",
        "total": len(urls),
        "phishing_detected": phishing_count,
        "legitimate_detected": len(urls) - phishing_count,
        "results": results,
    })


@app.route("/", methods=["GET"])
def index():
    """API root — show available endpoints."""
    return jsonify({
        "service": "Phishing URL Detector API",
        "version": "1.0.0",
        "author": "Caeser Mwania Mwathe — Maseno University CCS/00056/022",
        "endpoints": {
            "GET  /api/health":           "Health check",
            "GET  /api/model/info":       "Model performance metrics",
            "GET  /api/features":         "List of feature names",
            "POST /api/predict":          "Classify a single URL",
            "POST /api/predict/batch":    "Classify up to 100 URLs",
        },
        "example": {
            "request": "POST /api/predict",
            "body": {"url": "https://example.com"},
        },
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


# ══════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("=" * 55)
    logger.info("  PHISHING URL DETECTOR API")
    logger.info("=" * 55)

    try:
        load_model()
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)

    logger.info("Starting Flask server on http://localhost:5000")
    import os
port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port, debug=False)
    )
