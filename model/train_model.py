"""
Model Training — Phishing URL Detector
=======================================
Trains Random Forest and Gradient Boosting (XGBoost-equivalent) classifiers,
evaluates them, selects the best, and saves it for API deployment.

Usage:
    python train_model.py
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler

# Add parent to path so we can import feature_extractor
sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features_batch, get_feature_names

MODELS_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
DATA_DIR   = os.path.join(os.path.dirname(__file__), "..", "data")


def load_and_extract(split: str = "train") -> tuple:
    """Load CSV and extract features."""
    path = os.path.join(DATA_DIR, f"{split}.csv")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}\nRun data/prepare_dataset.py first.")

    df = pd.read_csv(path)
    print(f"[*] Extracting features for {split} set ({len(df)} URLs)...")
    t0 = time.time()
    X = extract_features_batch(df["url"].tolist(), verbose=True)
    y = df["label"].values
    print(f"[✓] Feature extraction done in {time.time() - t0:.1f}s — shape: {X.shape}")
    return X, y


def train_and_evaluate(model, X_train, y_train, X_test, y_test, model_name: str) -> dict:
    """Train a model and return evaluation metrics."""
    print(f"\n{'─'*55}")
    print(f"  Training: {model_name}")
    print(f"{'─'*55}")

    t0 = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"  Training time: {train_time:.2f}s")

    # Test set metrics
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc   = accuracy_score(y_test, y_pred)
    prec  = precision_score(y_test, y_pred, zero_division=0)
    rec   = recall_score(y_test, y_pred, zero_division=0)
    f1    = f1_score(y_test, y_pred, zero_division=0)
    auc   = roc_auc_score(y_test, y_prob)
    cm    = confusion_matrix(y_test, y_pred).tolist()

    # Cross-validation on train set
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy", n_jobs=-1)

    print(f"\n  Test Set Performance:")
    print(f"    Accuracy:  {acc*100:.2f}%")
    print(f"    Precision: {prec*100:.2f}%")
    print(f"    Recall:    {rec*100:.2f}%")
    print(f"    F1 Score:  {f1*100:.2f}%")
    print(f"    ROC-AUC:   {auc*100:.2f}%")
    print(f"\n  5-Fold CV Accuracy: {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n  Classification Report:")
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    for line in report.splitlines():
        print("    " + line)

    return {
        "model_name":   model_name,
        "accuracy":     round(acc, 6),
        "precision":    round(prec, 6),
        "recall":       round(rec, 6),
        "f1_score":     round(f1, 6),
        "roc_auc":      round(auc, 6),
        "cv_mean":      round(float(cv_scores.mean()), 6),
        "cv_std":       round(float(cv_scores.std()), 6),
        "confusion_matrix": cm,
        "train_time_s": round(train_time, 2),
    }


def get_feature_importance(model, feature_names: list, top_n: int = 20) -> list:
    """Extract feature importances from a tree-based model."""
    if not hasattr(model, "feature_importances_"):
        return []

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    result = []
    print(f"\n  Top {top_n} Most Important Features:")
    for i in range(min(top_n, len(feature_names))):
        idx = indices[i]
        name = feature_names[idx]
        imp = importances[idx]
        bar = "█" * int(imp * 200)
        print(f"    {i+1:2d}. {name:<35} {imp:.4f}  {bar}")
        result.append({"feature": name, "importance": round(float(imp), 6)})

    return result


def save_model(model, model_name: str, metrics: dict, feature_names: list, scaler=None):
    """Save model and metadata."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    safe_name = model_name.lower().replace(" ", "_")
    model_path = os.path.join(MODELS_DIR, f"{safe_name}.pkl")
    joblib.dump(model, model_path)

    if scaler:
        scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
        joblib.dump(scaler, scaler_path)

    meta = {
        **metrics,
        "feature_names": feature_names,
        "num_features": len(feature_names),
        "saved_at": datetime.now().isoformat(),
        "model_file": model_path,
    }
    meta_path = os.path.join(MODELS_DIR, f"{safe_name}_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n  [✓] Model saved: {model_path}")
    print(f"  [✓] Metadata:    {meta_path}")
    return model_path


def main():
    print("=" * 60)
    print("  PHISHING URL DETECTOR — Model Training")
    print("=" * 60)

    # ── Load data ──────────────────────────────────
    X_train, y_train = load_and_extract("train")
    X_test,  y_test  = load_and_extract("test")

    feature_names = get_feature_names()
    print(f"\n[✓] Features: {len(feature_names)}")
    print(f"[✓] Train: {len(y_train)} | Phishing: {y_train.sum()} | Legit: {(y_train==0).sum()}")
    print(f"[✓] Test:  {len(y_test)} | Phishing: {y_test.sum()} | Legit: {(y_test==0).sum()}")

    all_results = []

    # ── Model 1: Random Forest ─────────────────────
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf_metrics = train_and_evaluate(rf, X_train, y_train, X_test, y_test, "Random Forest")
    rf_imp = get_feature_importance(rf, feature_names)
    rf_metrics["feature_importance"] = rf_imp
    save_model(rf, "random_forest", rf_metrics, feature_names)
    all_results.append(("Random Forest", rf, rf_metrics))

    # ── Model 2: Gradient Boosting (XGBoost equiv) ─
    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=6,
        min_samples_split=5,
        subsample=0.8,
        max_features="sqrt",
        random_state=42,
    )
    gb_metrics = train_and_evaluate(gb, X_train, y_train, X_test, y_test, "Gradient Boosting")
    gb_imp = get_feature_importance(gb, feature_names)
    gb_metrics["feature_importance"] = gb_imp
    save_model(gb, "gradient_boosting", gb_metrics, feature_names)
    all_results.append(("Gradient Boosting", gb, gb_metrics))

    # ── Select Best Model ──────────────────────────
    print(f"\n{'='*60}")
    print("  MODEL COMPARISON")
    print(f"{'='*60}")
    print(f"{'Model':<25} {'Accuracy':>10} {'F1':>10} {'ROC-AUC':>10}")
    print("─" * 60)
    for name, _, metrics in all_results:
        print(f"{name:<25} {metrics['accuracy']*100:>9.2f}% {metrics['f1_score']*100:>9.2f}% {metrics['roc_auc']*100:>9.2f}%")

    best_name, best_model, best_metrics = max(all_results, key=lambda x: x[2]["f1_score"])
    print(f"\n[★] Best Model: {best_name} (F1={best_metrics['f1_score']*100:.2f}%)")

    # Save best model as default
    best_model_path = os.path.join(MODELS_DIR, "best_model.pkl")
    joblib.dump(best_model, best_model_path)

    best_meta = {
        **best_metrics,
        "model_name": best_name,
        "feature_names": feature_names,
        "saved_at": datetime.now().isoformat(),
    }
    best_meta_path = os.path.join(MODELS_DIR, "best_model_meta.json")
    with open(best_meta_path, "w") as f:
        json.dump(best_meta, f, indent=2)

    print(f"[✓] Best model saved as: {best_model_path}")
    print(f"\n{'='*60}")
    print("  TRAINING COMPLETE")
    print(f"{'='*60}")
    print(f"\nBest model: {best_name}")
    print(f"Accuracy:   {best_metrics['accuracy']*100:.2f}%")
    print(f"F1 Score:   {best_metrics['f1_score']*100:.2f}%")
    print(f"ROC-AUC:    {best_metrics['roc_auc']*100:.2f}%")
    print(f"\nTo run the API: cd ../api && python app.py")


if __name__ == "__main__":
    main()
