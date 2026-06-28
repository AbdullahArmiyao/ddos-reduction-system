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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "stage1", "training_data.csv")
MODEL_PATH = os.path.join(SCRIPT_DIR, "ddos_rf_model.joblib")
FEATURE_COLS = [
    "entropy",
    "ewma_rate",
    "mean_h",
    "mean_r",
    "sigma_h",
    "sigma_r",
    "proto_ratio",
    "dominant_ip_ratio",
    "delta_rate",
    "delta_entropy"
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
    
    # Calculate delta features
    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]
    
    initial_len = len(df)
    
    # Mask for contaminated Normal rows (Label 0 but rate is abnormally high)
    normal_contamination_mask = (df[LABEL_COL] == 0) & (df["ewma_rate"] > 1000.0)
    
    # Mask for DDoS startup/transient rows (Label 2 but rate is abnormally low)
    ddos_transient_mask = (df[LABEL_COL] == 2) & (df["ewma_rate"] < 5000.0)
    
    # Filter out both sets of contaminated rows
    df_cleaned = df[~(normal_contamination_mask | ddos_transient_mask)].copy()
    
    cleaned_len = len(df_cleaned)
    pruned_count = initial_len - cleaned_len
    print(f"[+] Pruned {pruned_count} contaminated/transient rows ({pruned_count/initial_len*100:.2f}% of data).")
    print(f"[+] Cleaned dataset size: {cleaned_len} rows.")
    # 2.5 Inject Synthetic Boundary Cases to Prevent Overfitting & Ensure Generalization
    print("[+] Injecting synthetic edge cases for robust generalization...")
    synthetic_rows = []
    
    # 50 Single-Source DDoS cases (UDP/ICMP floods)
    for _ in range(50):
        synthetic_rows.append({
            "entropy": np.random.uniform(0.0, 1.5),
            "ewma_rate": np.random.uniform(10000.0, 150000.0),
            "mean_h": np.random.uniform(3.5, 4.5),
            "mean_r": np.random.uniform(20.0, 100.0),
            "sigma_h": np.random.uniform(0.05, 0.2),
            "sigma_r": np.random.uniform(5.0, 15.0),
            "proto_ratio": np.random.uniform(0.0, 0.3),
            "dominant_ip_ratio": np.random.uniform(0.6, 1.0),
            "delta_rate": np.random.uniform(9900.0, 149900.0),
            "delta_entropy": np.random.uniform(-4.5, -2.0),
            LABEL_COL: 2 # DDoS
        })
        
    # 50 Single-Source DDoS cases (TCP floods)
    for _ in range(50):
        synthetic_rows.append({
            "entropy": np.random.uniform(0.0, 1.5),
            "ewma_rate": np.random.uniform(10000.0, 150000.0),
            "mean_h": np.random.uniform(3.5, 4.5),
            "mean_r": np.random.uniform(20.0, 100.0),
            "sigma_h": np.random.uniform(0.05, 0.2),
            "sigma_r": np.random.uniform(5.0, 15.0),
            "proto_ratio": np.random.uniform(0.7, 1.0),
            "dominant_ip_ratio": np.random.uniform(0.6, 1.0),
            "delta_rate": np.random.uniform(9900.0, 149900.0),
            "delta_entropy": np.random.uniform(-4.5, -2.0),
            LABEL_COL: 2 # DDoS
        })

    # 100 Spoofed / Distributed DDoS cases (High rate, high entropy, low dominant IP)
    for _ in range(100):
        synthetic_rows.append({
            "entropy": np.random.uniform(3.5, 5.5),
            "ewma_rate": np.random.uniform(15000.0, 150000.0), # Higher rate than Flash Crowd
            "mean_h": np.random.uniform(3.5, 4.5),
            "mean_r": np.random.uniform(20.0, 100.0),
            "sigma_h": np.random.uniform(0.05, 0.2),
            "sigma_r": np.random.uniform(5.0, 15.0),
            "proto_ratio": np.random.uniform(0.0, 1.0),
            "dominant_ip_ratio": np.random.uniform(0.01, 0.25),
            "delta_rate": np.random.uniform(14900.0, 149900.0),
            "delta_entropy": np.random.uniform(-0.5, 0.5),
            LABEL_COL: 2 # DDoS
        })
        
    # 100 Flash Crowd cases (Moderate-high rate, high entropy, low dominant IP)
    for _ in range(100):
        synthetic_rows.append({
            "entropy": np.random.uniform(3.5, 5.5),
            "ewma_rate": np.random.uniform(2000.0, 8000.0), # Legitimate flash crowd limits
            "mean_h": np.random.uniform(3.5, 4.5),
            "mean_r": np.random.uniform(20.0, 100.0),
            "sigma_h": np.random.uniform(0.05, 0.2),
            "sigma_r": np.random.uniform(5.0, 15.0),
            "proto_ratio": np.random.uniform(0.7, 1.0), # Mostly TCP
            "dominant_ip_ratio": np.random.uniform(0.01, 0.2),
            "delta_rate": np.random.uniform(1900.0, 7900.0),
            "delta_entropy": np.random.uniform(-0.5, 0.5),
            LABEL_COL: 1 # Flash Crowd
        })
        
    # 100 Clean Normal cases (Low rate, varying entropy and dominant IP)
    for _ in range(100):
        synthetic_rows.append({
            "entropy": np.random.uniform(1.0, 5.5),
            "ewma_rate": np.random.uniform(5.0, 800.0), # Always low rate
            "mean_h": np.random.uniform(1.0, 5.5),
            "mean_r": np.random.uniform(5.0, 800.0),
            "sigma_h": np.random.uniform(0.05, 0.5),
            "sigma_r": np.random.uniform(1.0, 50.0),
            "proto_ratio": np.random.uniform(0.0, 1.0),
            "dominant_ip_ratio": np.random.uniform(0.02, 0.6),
            "delta_rate": np.random.uniform(-100.0, 100.0),
            "delta_entropy": np.random.uniform(-0.5, 0.5),
            LABEL_COL: 0 # Normal
        })
        
    df_synthetic = pd.DataFrame(synthetic_rows)
    df_cleaned = pd.concat([df_cleaned, df_synthetic], ignore_index=True)

    print("\n--- Cleaned Class Distribution (Before Balancing) ---")
    print(df_cleaned[LABEL_COL].value_counts().to_string())
    
    # Rebalance by upsampling minority classes to match majority class
    from sklearn.utils import resample
    
    df_normal = df_cleaned[df_cleaned[LABEL_COL] == 0]
    df_flash = df_cleaned[df_cleaned[LABEL_COL] == 1]
    df_ddos = df_cleaned[df_cleaned[LABEL_COL] == 2]
    
    if len(df_normal) > 0 and len(df_flash) > 0 and len(df_ddos) > 0:
        max_size = max(len(df_normal), len(df_flash), len(df_ddos))
        df_normal_upsampled = resample(df_normal, replace=True, n_samples=max_size, random_state=42)
        df_flash_upsampled = resample(df_flash, replace=True, n_samples=max_size, random_state=42)
        df_ddos_upsampled = resample(df_ddos, replace=True, n_samples=max_size, random_state=42)
        df_balanced = pd.concat([df_normal_upsampled, df_flash_upsampled, df_ddos_upsampled], ignore_index=True)
        print(f"[+] Balanced dataset size via upsampling: {len(df_balanced)} rows.")
    else:
        df_balanced = df_cleaned
        print("[!] Cannot balance classes; one or more classes are missing after cleaning.")
        
    print("\n--- Balanced Class Distribution ---")
    print(df_balanced[LABEL_COL].value_counts().to_string())
    
    if len(df_balanced) < 100:
        print("[-] Warning: Dataset is very small. Classification results may be unreliable.")
        
    # 3. Train/Test Split
    X = df_balanced[FEATURE_COLS]
    y = df_balanced[LABEL_COL]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Train Random Forest Model
    print(f"\n[+] Training Random Forest Classifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=5, # Reduced from 10 to prevent overfitting and force high-level decisions
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
