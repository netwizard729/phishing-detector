"""
Dataset Preparation for Phishing URL Detector
=============================================
Loads your Kaggle CSV and prepares train/test splits.

Usage:
    python prepare_dataset.py --dataset ~/phishing_site_urls.csv
"""

import pandas as pd
import os
import sys
import json
import argparse
from datetime import datetime
from sklearn.model_selection import train_test_split

KNOWN_MAPPINGS = [
    ("URL",    "Label",  "bad",        "good"),
    ("url",    "status", "phishing",   "legitimate"),
    ("url",    "label",  "phishing",   "legitimate"),
    ("url",    "label",  1,            0),
    ("url",    "type",   "phishing",   "legitimate"),
    ("URL",    "label",  "phishing",   "benign"),
    ("url",    "class",  1,            0),
    ("domain", "label",  1,            0),
    ("url",    "result", -1,           1),
]


def load_csv(filepath):
    for enc in ["utf-8", "latin-1", "cp1252"]:
        try:
            df = pd.read_csv(filepath, encoding=enc, low_memory=False)
            print(f"    Encoding: {enc}")
            return df
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Could not read file: {filepath}")


def detect_and_load(filepath):
    print(f"[*] Loading: {filepath}")
    df = load_csv(filepath)
    df.columns = df.columns.str.strip()
    print(f"    Rows   : {len(df):,}")
    print(f"    Columns: {list(df.columns)}")

    col_lower = {c.lower(): c for c in df.columns}

    for url_col, label_col, phish_val, legit_val in KNOWN_MAPPINGS:
        url_c   = col_lower.get(url_col.lower())
        label_c = col_lower.get(label_col.lower())
        if not url_c or not label_c:
            continue
        sample_vals = [str(v).lower().strip() for v in df[label_c].dropna().unique()]
        phish_str   = str(phish_val).lower().strip()
        legit_str   = str(legit_val).lower().strip()
        if phish_str in sample_vals or legit_str in sample_vals:
            print(f"    Detected: url='{url_c}'  label='{label_c}'")
            print(f"    Mapping : '{phish_val}' -> phishing(1)  '{legit_val}' -> legit(0)")
            out = pd.DataFrame()
            out["url"]   = df[url_c].astype(str).str.strip()
            out["label"] = df[label_c].apply(
                lambda x: 1 if str(x).lower().strip() == phish_str else 0
            )
            out = out.dropna()
            print(f"\n    Raw counts:\n{out['label'].value_counts().to_string()}")
            return out

    # Fallback
    print("    [!] Auto-detecting columns...")
    url_c = label_c = None
    for col in df.columns:
        cl = col.lower()
        if cl in ["url","urls","address","link","domain","site"]: url_c = col
        if cl in ["label","class","type","status","result","target","phishing"]: label_c = col
    if not url_c:
        for col in df.columns:
            sample = df[col].dropna().astype(str).head(20)
            if sample.str.contains(r"https?://|www\.", regex=True).mean() > 0.5:
                url_c = col; break
    if not url_c:
        print(f"[X] Could not find URL column. Columns: {list(df.columns)}")
        sys.exit(1)

    out = pd.DataFrame()
    out["url"] = df[url_c].astype(str).str.strip()
    if label_c:
        def normalize(v):
            v = str(v).lower().strip()
            if v in ["1","phishing","bad","malicious","phish","-1"]: return 1
            if v in ["0","legitimate","good","benign","safe","legit"]: return 0
            return None
        out["label"] = df[label_c].apply(normalize)
    else:
        out["label"] = 1
    out = out.dropna()
    print(f"\n    Raw counts:\n{out['label'].value_counts().to_string()}")
    return out


def balance(df, max_per_class=10000):
    phish = df[df["label"] == 1]
    legit = df[df["label"] == 0]
    n = min(len(phish), len(legit), max_per_class)
    if n == 0:
        print("[X] No usable data. Check your CSV labels."); sys.exit(1)
    print(f"\n[*] Balancing: Phishing={len(phish):,}  Legit={len(legit):,}  -> using {n:,} each")
    return pd.concat([
        phish.sample(n, random_state=42),
        legit.sample(n, random_state=42),
    ]).sample(frac=1, random_state=42).reset_index(drop=True)


def save_splits(df, output_dir, test_size=0.2):
    os.makedirs(output_dir, exist_ok=True)
    train_df, test_df = train_test_split(
        df, test_size=test_size, stratify=df["label"], random_state=42
    )
    train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False)
    test_df.to_csv(os.path.join(output_dir,  "test.csv"),  index=False)
    df.to_csv(os.path.join(output_dir, "full_dataset.csv"), index=False)

    meta = {
        "total": len(df), "train": len(train_df), "test": len(test_df),
        "phishing_train": int(train_df["label"].sum()),
        "legit_train":    int((train_df["label"]==0).sum()),
        "phishing_test":  int(test_df["label"].sum()),
        "legit_test":     int((test_df["label"]==0).sum()),
        "source": "kaggle", "created_at": datetime.now().isoformat(),
    }
    with open(os.path.join(output_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n[OK] Saved to {output_dir}/")
    print(f"    full_dataset.csv  {len(df):,} URLs")
    print(f"    train.csv         {len(train_df):,} URLs")
    print(f"    test.csv          {len(test_df):,} URLs")
    print(f"\n    Phishing  train={meta['phishing_train']:,}  test={meta['phishing_test']:,}")
    print(f"    Legit     train={meta['legit_train']:,}  test={meta['legit_test']:,}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", "-d", required=True,
        help="Path to Kaggle CSV  e.g. ~/phishing_site_urls.csv")
    parser.add_argument("--max-per-class", "-m", type=int, default=10000)
    args = parser.parse_args()

    print("="*60)
    print("  PHISHING URL DETECTOR — Dataset Preparation")
    print("="*60); print()

    csv_path = os.path.expanduser(args.dataset)
    if not os.path.exists(csv_path):
        print(f"[X] File not found: {csv_path}"); sys.exit(1)

    df      = detect_and_load(csv_path)
    df      = balance(df, max_per_class=args.max_per_class)
    out_dir = os.path.dirname(os.path.abspath(__file__))
    save_splits(df, out_dir)

    print(f"\n[OK] Done! Next: python model/train_model.py")
