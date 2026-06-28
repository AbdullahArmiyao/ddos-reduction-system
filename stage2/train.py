#!/usr/bin/env python3
"""
train.py — Stage 2: Machine Learning Model Trainer
-------------------------------------------------
This script loads the raw CSV data collected from Stage 1, applies strict
preprocessing/cleaning rules to remove timing-jitter baseline contamination,
trains a Random Forest classifier, and saves the trained model.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# Configuration
CSV_PATH = "../stage1/training_data.csv"
MODEL_PATH = "ddos_rf_model.joblib"
FEATURE_COLS = [
    "entropy",
    "ewma_rate",
    "mean_h",
    "mean_r",
    "sigma_h",
    "sigma_r",
    "proto_ratio",
    "dominant_ip_ratio"
]
LABEL_COL = "label"

def main():
    print("=== DDoS Reduction Project: Stage 2 Training ===")
    
    # 1. Load Dataset
    csv_file = CSV_PATH
    if not os.path.exists(csv_file):
        # Check current directory just in case
        csv_file = "training_data.csv"
        if not os.path.exists(csv_file):
            print(f"[-] Error: Training data not found at '{CSV_PATH}' or './training_data.csv'")
            print("    Please copy the collected CSV file to this directory and run again.")
            sys.exit(1)
            
    print(f"[+] Loading dataset from: {csv_file}")
    df = pd.read_csv(csv_file)
    print(f"[+] Loaded {len(df)} raw rows.")
    
    print("\n--- Raw Class Distribution ---")
    print(df[LABEL_COL].value_counts().to_string())
    
    # 2. Clean Dataset (Pruning Contaminated Rows)
    #
    # Issue: Timing jitter causes the Rust EWMA rate to occasionally spike to 
    # hundreds of thousands of pps even during low-rate normal baseline (Label 0).
    #
    # We prune:
    #   - Label 0 (Normal) rows where ewma_rate > 10,000 pps (clearly anomalous/jitter).
    #   - Label 2 (DDoS) rows where ewma_rate < 10,000 pps (transients/warm-up periods).
    #   - Rows containing NaN/inf.
    
    print("\n[+] Preprocessing & cleaning dataset...")
    
    # Drop rows with NaN or infinite values
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    initial_len = len(df)
    
    # Mask for contaminated Normal rows (Label 0 but rate is abnormally high)
    normal_contamination_mask = (df[LABEL_COL] == 0) & (df["ewma_rate"] > 10000.0)
    
    # Mask for DDoS startup/transient rows (Label 2 but rate is abnormally low)
    ddos_transient_mask = (df[LABEL_COL] == 2) & (df["ewma_rate"] < 10000.0)
    
    # Filter out both sets of contaminated rows
    df_cleaned = df[~(normal_contamination_mask | ddos_transient_mask)].copy()
    
    cleaned_len = len(df_cleaned)
    pruned_count = initial_len - cleaned_len
    print(f"[+] Pruned {pruned_count} contaminated/transient rows ({pruned_count/initial_len*100:.2f}% of data).")
    print(f"[+] Cleaned dataset size: {cleaned_len} rows.")
    
    print("\n--- Cleaned Class Distribution ---")
    print(df_cleaned[LABEL_COL].value_counts().to_string())
    
    if cleaned_len < 100:
        print("[-] Warning: Dataset is very small. Classification results may be unreliable.")
        
    # 3. Train/Test Split
    X = df_cleaned[FEATURE_COLS]
    y = df_cleaned[LABEL_COL]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Train Random Forest Model
    print(f"\n[+] Training Random Forest Classifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced", # Helps with class imbalance
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    print("[+] Model training complete.")
    
    # 5. Evaluate Model
    print("\n[+] Evaluating model on holdout test set...")
    y_pred = clf.predict(X_test)
    
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=["Normal (0)", "Flash Crowd (1)", "DDoS (2)"]))
    
    print("\n--- Confusion Matrix ---")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature Importances
    print("\n--- Feature Importances ---")
    importances = clf.feature_importances_
    for col, imp in sorted(zip(FEATURE_COLS, importances), key=lambda x: x[1], reverse=True):
        print(f"  {col:<20} : {imp:.4f}")
        
    # 6. Save Model
    print(f"\n[+] Saving trained model to: {MODEL_PATH}")
    joblib.dump(clf, MODEL_PATH)
    print("[+] Done!")

if __name__ == "__main__":
    main()
