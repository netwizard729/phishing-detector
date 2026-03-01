"""
Dataset Preparation for Phishing URL Detector
=============================================
Supports real Kaggle datasets AND synthetic fallback.

RECOMMENDED KAGGLE DATASETS (free, no login needed via direct URL):
  1. https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls
     File: phishing_site_urls.csv  (columns: URL, Label)

  2. https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
     File: dataset.csv  (columns: url, status)

  3. https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector
     File: phishing.csv

HOW TO USE A KAGGLE DATASET:
  1. Download the CSV from Kaggle
  2. Place it anywhere (e.g. ~/Downloads/phishing_site_urls.csv)
  3. Run:
       python data/prepare_dataset.py --dataset ~/Downloads/phishing_site_urls.csv
  4. That's it. The script auto-detects column names and label formats.

Run without arguments to use the synthetic fallback:
       python data/prepare_dataset.py
"""

import pandas as pd
import numpy as np
import random
import string
import os
import sys
import json
import argparse
from datetime import datetime

random.seed(42)
np.random.seed(42)

# ─────────────────────────────────────────────
# KNOWN KAGGLE DATASET COLUMN MAPPINGS
# ─────────────────────────────────────────────
KNOWN_MAPPINGS = [
    ("URL",    "Label",  "bad",       "good"),
    ("url",    "status", "phishing",  "legitimate"),
    ("url",    "label",  "phishing",  "legitimate"),
    ("url",    "label",  1,           0),
    ("url",    "type",   "phishing",  "legitimate"),
    ("URL",    "label",  "phishing",  "benign"),
    ("url",    "class",  1,           0),
    ("domain", "label",  1,           0),
    ("url",    "result", -1,          1),
]


def detect_and_load(filepath):
    print(f"[*] Loading dataset: {filepath}")
    df = None
    for enc in ["utf-8", "latin-1", "cp1252"]:
        try:
            df = pd.read_csv(filepath, encoding=enc, low_memory=False)
            break
        except UnicodeDecodeError:
            continue
    if df is None:
        raise ValueError("Could not read file with any known encoding.")

    df.columns = df.columns.str.strip()
    print(f"    Rows: {len(df):,}  |  Columns: {list(df.columns)}")

    for url_col, label_col, phish_val, legit_val in KNOWN_MAPPINGS:
        col_map = {c.lower(): c for c in df.columns}
        url_c   = col_map.get(url_col.lower())
        label_c = col_map.get(label_col.lower())
        if url_c and label_c:
            label_vals = [str(v).lower().strip() for v in df[label_c].dropna().unique()]
            phish_str  = str(phish_val).lower().strip()
            legit_str  = str(legit_val).lower().strip()
            if phish_str in label_vals or legit_str in label_vals:
                print(f"    Detected format: url='{url_c}', label='{label_c}'")
                out = pd.DataFrame()
                out["url"]   = df[url_c].astype(str).str.strip()
                out["label"] = df[label_c].apply(
                    lambda x: 1 if str(x).lower().strip() == phish_str else 0
                )
                return out.dropna()

    # Fallback auto-detect
    print("    [!] Auto-detecting columns...")
    url_col = label_col = None
    for col in df.columns:
        cl = col.lower()
        if cl in ["url","urls","address","link","domain","site"]:
            url_col = col
        if cl in ["label","class","type","status","result","target","phishing"]:
            label_col = col
    if not url_col:
        for col in df.columns:
            sample = df[col].dropna().astype(str).head(20)
            if sample.str.contains(r"https?://|www\.", regex=True).mean() > 0.5:
                url_col = col
                break
    if not url_col:
        raise ValueError(
            f"Cannot find URL column.\nColumns: {list(df.columns)}\n"
            "Rename your URL column to 'url' and label column to 'label'."
        )
    out = pd.DataFrame()
    out["url"] = df[url_col].astype(str).str.strip()
    if label_col:
        def norm(v):
            v = str(v).lower().strip()
            if v in ["1","phishing","bad","malicious","phish","-1"]: return 1
            if v in ["0","legitimate","good","benign","safe","legit"]: return 0
            return None
        out["label"] = df[label_col].apply(norm)
    else:
        out["label"] = 1
    return out.dropna()


def balance_dataset(df, max_per_class=10000):
    phish = df[df["label"] == 1]
    legit = df[df["label"] == 0]
    n = min(len(phish), len(legit), max_per_class)
    print(f"\n[*] Balancing: Phishing={len(phish):,}  Legit={len(legit):,}  → using {n:,} each")
    return pd.concat([
        phish.sample(n, random_state=42),
        legit.sample(n, random_state=42),
    ]).sample(frac=1, random_state=42).reset_index(drop=True)


def split_and_save(df, output_dir, test_size=0.2):
    from sklearn.model_selection import train_test_split
    os.makedirs(output_dir, exist_ok=True)
    train_df, test_df = train_test_split(df, test_size=test_size, stratify=df["label"], random_state=42)
    train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False)
    test_df.to_csv(os.path.join(output_dir,  "test.csv"),  index=False)
    meta = {
        "total": len(df), "train": len(train_df), "test": len(test_df),
        "phishing_train": int(train_df["label"].sum()),
        "legit_train":    int((train_df["label"]==0).sum()),
        "phishing_test":  int(test_df["label"].sum()),
        "legit_test":     int((test_df["label"]==0).sum()),
        "created_at":     datetime.now().isoformat(),
    }
    with open(os.path.join(output_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\n[✓] Train: {len(train_df):,}  |  Test: {len(test_df):,}")
    print(f"    Phishing  — train: {meta['phishing_train']:,}  test: {meta['phishing_test']:,}")
    print(f"    Legit     — train: {meta['legit_train']:,}  test: {meta['legit_test']:,}")
    return train_df, test_df


# ── Synthetic fallback ──────────────────────────────────────────
LEGIT_DOMAINS = ["google.com","youtube.com","facebook.com","amazon.com","twitter.com",
    "wikipedia.org","linkedin.com","instagram.com","microsoft.com","apple.com",
    "github.com","stackoverflow.com","reddit.com","netflix.com","paypal.com",
    "ebay.com","bbc.com","cnn.com","dropbox.com","zoom.us","slack.com",
    "safaricom.co.ke","kcbgroup.com","equitybank.co.ke","nation.africa"]
LEGIT_PATHS = ["/","/home","/about","/login","/products","/services","/blog",
    "/news","/faq","/help","/support","/pricing","/dashboard","/search"]
PHISH_TARGETS = ["paypal","apple","microsoft","amazon","facebook","google",
    "netflix","instagram","wellsfargo","bankofamerica","ebay","mpesa","safaricom"]
PHISH_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".online",".pw"]
PHISH_WORDS = ["secure","login","verify","update","confirm","account","signin","alert"]

def _r(n=8): return "".join(random.choices(string.ascii_lowercase+string.digits, k=n))

def gen_legit():
    s = "https" if random.random()>0.05 else "http"
    q = f"?id={random.randint(1,9999)}" if random.random()>0.7 else ""
    return f"{s}://{random.choice(LEGIT_DOMAINS)}{random.choice(LEGIT_PATHS)}{q}"

def gen_phish():
    t=random.choice(PHISH_TARGETS); tld=random.choice(PHISH_TLDS)
    w=random.choice(PHISH_WORDS);   s="http" if random.random()>0.3 else "https"
    p=random.choice(["typo","sub","ip","long","rand","kw"])
    if p=="typo":
        for o,n in {"a":"4","e":"3","i":"1","o":"0"}.items():
            if o in t: t=t.replace(o,n,1); break
        return f"{s}://{t}{tld}/{w}"
    elif p=="sub":  return f"{s}://{t}.legit.com.{_r(6)}.tk/login.php"
    elif p=="ip":
        ip=".".join(str(random.randint(1,254)) for _ in range(4))
        return f"{s}://{ip}/{t}/login?s={_r(16)}"
    elif p=="long": return f"{s}://{w}-{t}-{w}.{_r(6)}{tld}/signin.php"
    elif p=="rand": return f"{s}://{_r(8)}{tld}/{t}/{w}/index.html"
    else:           return f"{s}://{t}-{w}{tld}/secure/login.php"

def generate_synthetic(n=10000):
    print(f"[*] Generating {n:,} legitimate + {n:,} phishing URLs...")
    df = pd.concat([
        pd.DataFrame({"url":[gen_legit() for _ in range(n)], "label":0}),
        pd.DataFrame({"url":[gen_phish() for _ in range(n)], "label":1}),
    ]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[✓] Synthetic dataset ready: {len(df):,} URLs")
    return df


# ── Entry point ─────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare phishing URL dataset")
    parser.add_argument("--dataset", "-d", type=str, default=None,
        help="Path to Kaggle CSV (e.g. ~/Downloads/phishing_site_urls.csv)")
    parser.add_argument("--max-per-class", "-m", type=int, default=10000,
        help="Max URLs per class (default: 10000)")
    args = parser.parse_args()

    print("="*60)
    print("  PHISHING URL DETECTOR — Dataset Preparation")
    print("="*60); print()

    data_dir = os.path.dirname(os.path.abspath(__file__))

    if args.dataset:
        path = os.path.expanduser(args.dataset)
        if not os.path.exists(path):
            print(f"[✗] File not found: {path}"); sys.exit(1)
        df = detect_and_load(path)
        print(f"\n    Label distribution:\n{df['label'].value_counts().to_string()}")
        df = balance_dataset(df, max_per_class=args.max_per_class)
    else:
        print("No dataset provided — using synthetic data.")
        print("To use a real Kaggle dataset:")
        print("  python data/prepare_dataset.py --dataset ~/Downloads/phishing_site_urls.csv\n")
        df = generate_synthetic(n=args.max_per_class)

    df.to_csv(os.path.join(data_dir, "full_dataset.csv"), index=False)
    print(f"\n[✓] Full dataset → data/full_dataset.csv")
    split_and_save(df, data_dir)
    print("\n[✓] Done! Next: python model/train_model.py")
