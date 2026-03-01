# 🛡️ Phishing URL Detector
**CCS 413 Computer Science Project — Maseno University**  
*Caeser Mwania Mwathe · CCS/00056/022*

> A machine learning system that detects phishing URLs in real-time using 46 URL-based, lexical, and domain features. Achieves **99.98–100% accuracy** with a Flask REST API and Chrome/Firefox browser extension.

---

## 📁 Project Structure

```
phishing-detector/
├── data/
│   ├── prepare_dataset.py     ← Dataset generation & preprocessing
│   ├── train.csv              ← Generated after running prepare_dataset.py
│   ├── test.csv
│   ├── full_dataset.csv
│   └── metadata.json
│
├── model/
│   ├── feature_extractor.py   ← 46-feature extraction engine
│   ├── train_model.py         ← Trains Random Forest + Gradient Boosting
│   └── saved_models/
│       ├── best_model.pkl     ← Best model (auto-selected)
│       ├── random_forest.pkl
│       ├── gradient_boosting.pkl
│       └── *_meta.json        ← Metrics & feature importances
│
├── api/
│   └── app.py                 ← Flask REST API (5 endpoints)
│
├── extension/
│   ├── manifest.json          ← Chrome/Firefox MV3 manifest
│   ├── background.js          ← Service worker (auto-checks every page)
│   ├── popup.html             ← Extension popup UI
│   ├── content.js             ← Inline warning banner injector
│   └── icons/                 ← Extension icons (add your own PNGs)
│
└── tests/
    └── test_all.py            ← 25-test suite (100% passing)
```

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install scikit-learn pandas numpy flask joblib requests
```

### 2. Prepare Dataset
```bash
python data/prepare_dataset.py
```
Generates 20,000 URLs (10,000 phishing + 10,000 legitimate) and splits into train/test.

> **Using a real dataset (recommended for submission)?**
> ```python
> from data.prepare_dataset import load_real_dataset, split_and_save
> df = load_real_dataset("your_kaggle_dataset.csv")   # PhishTank, OpenPhish, Kaggle
> split_and_save(df, "data")
> ```

### 3. Train the Model
```bash
python model/train_model.py
```
Trains Random Forest and Gradient Boosting, prints metrics, saves best model.

### 4. Start the API
```bash
python api/app.py
```
API runs at `http://localhost:5000`

### 5. Run Tests
```bash
python tests/test_all.py
```

---

## 🔬 Features (46 total)

| Category | Features |
|---|---|
| **Length** | url_length, domain_length, path_length, query_length, subdomain_length, hostname_length |
| **Special Characters** | num_dots, num_hyphens, num_underscores, num_slashes, num_at_signs, num_percent, num_digits, … |
| **Binary Signals** | is_https, has_ip, has_at_sign, has_double_slash, has_prefix_suffix, is_shortened_url |
| **TLD Analysis** | is_suspicious_tld (.tk .xyz .click …), is_trusted_tld (.com .org .gov …) |
| **Keyword Detection** | num_phishing_keywords, has_login_keyword, has_secure_keyword, has_verify_keyword |
| **Entropy & Ratios** | url_entropy, domain_entropy, digit_ratio_url, vowel_ratio_domain |
| **Path & Query** | num_query_params, path_depth, has_php_extension, has_html_extension |
| **Domain Analysis** | subdomain_count, brand_in_subdomain, has_port |

**Top predictors (by feature importance):**
1. `is_trusted_tld` — legitimate domains use .com/.org/.gov
2. `num_phishing_keywords` — presence of "login", "verify", "secure" etc.
3. `digit_ratio_domain` — phishing domains use more digits
4. `is_suspicious_tld` — .tk, .xyz, .click highly correlated with phishing
5. `has_php_extension` — phishing often uses login.php

---

## 🌐 API Reference

**Base URL:** `http://localhost:5000`

### `GET /api/health`
```json
{ "status": "healthy", "model": "Gradient Boosting", "accuracy": "100.00%" }
```

### `POST /api/predict`
```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure.tk/verify.php"}'
```
**Response:**
```json
{
  "prediction": "phishing",
  "is_phishing": true,
  "phishing_probability": 100.0,
  "risk_level": "HIGH",
  "risk_color": "red",
  "signals": [
    "Suspicious top-level domain",
    "3 phishing keywords detected",
    ".php extension in phishing-heavy path"
  ],
  "features_summary": {
    "url_length": 40,
    "is_https": false,
    "has_ip": false,
    "suspicious_tld": true,
    "phishing_keywords": 3,
    "subdomain_depth": 0,
    "entropy": 4.52
  },
  "prediction_time_ms": 12.3,
  "confidence": 100.0
}
```

### `POST /api/predict/batch`
```json
{ "urls": ["https://google.com", "http://evil.tk/login.php", "..."] }
```
Max 100 URLs per request.

### `GET /api/model/info`
Returns model performance metrics and top feature importances.

### `GET /api/features`
Returns the list of all 46 feature names.

---

## 🔌 Browser Extension Setup

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `extension/` folder

> **Add icons:** Place PNG files named `icon16.png`, `icon32.png`, `icon48.png`, `icon128.png` in `extension/icons/`

**Extension features:**
- 🔴 **Red badge** on phishing sites
- ✅ **Green badge** on safe sites  
- 🚨 **Inline warning banner** on HIGH-risk pages (with "Go Back" button)
- 📊 **Popup** shows risk level, probability bar, detection signals, and session stats
- 🔍 **Manual URL checker** in popup

---

## 📊 Model Performance

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|---|---|---|---|---|---|
| Random Forest | 99.98% | 100.00% | 99.95% | 99.97% | 100.00% |
| **Gradient Boosting** ⭐ | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |

*5-fold cross-validation accuracy: 99.99% ± 0.02%*

**Performance specs:**
- Prediction latency: ~12ms per URL
- Model size: ~42MB  
- Feature extraction: <1ms per URL

---

## 🗄️ Using Real Datasets

Download from:
- **PhishTank** — https://phishtank.org/developer_info.php (CSV export)
- **OpenPhish** — https://openphish.com/phishing_feeds.html
- **Kaggle** — Search "phishing URLs dataset"
- **UCI ML Repository** — Phishing Websites Dataset

Then load with:
```python
from data.prepare_dataset import load_real_dataset, split_and_save
df = load_real_dataset("phishtank_verified_online.csv")
split_and_save(df, "data")
```

---

## 🔭 Future Work (from proposal)

- [ ] Integrate XGBoost (install with: `pip install xgboost`)
- [ ] Add WHOIS/domain age lookup via python-whois
- [ ] Deep learning hybrid (CNN on URL character embeddings)
- [ ] SHAP values for explainable AI
- [ ] Mobile app (Android/iOS)
- [ ] Continuous learning from user feedback
- [ ] Email/SMS phishing detection (NLP)

---

## 📚 References

- Alkhalil et al. (2021). Phishing attacks: A recent comprehensive study. *Frontiers in Computer Science*.
- Aljofey et al. (2023). A deep learning-based approach for phishing URL detection. *Scientific Reports*.
- Anti-Phishing Working Group. (2024). Phishing Activity Trends Report.
- Bu & Kim (2021). Deep character-level anomaly detection for zero-day phishing. *Electronics*.
- Mohammad et al. (2022). Intelligent rule-based phishing classification. *IET Information Security*.

---

*Maseno University · School of Computing and Informatics · Department of Computer Science*
# phishing-detector
