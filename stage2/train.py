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
from sklearn.utils import resample

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
        csv_file = "training_data.csv"
        if not os.path.exists(csv_file):
            print(f"[-] Error: Training data not found at '{CSV_PATH}' or './training_data.csv'")
            print("    Please copy the collected CSV file to this directory and run again.")
            sys.exit(1)
            
    print(f"[+] Loading dataset from: {csv_file}")
    df = pd.read_csv(csv_file)
    print(f"[+] Loaded {len(df)} raw rows.")
    
    # Drop rows with NaN or infinite values
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    
    # Filter out flash-crowd warm-up rows (rate < 100) that blur the boundary with Normal traffic
    df = df[~((df[LABEL_COL] == 1) & (df["ewma_rate"] < 100))].reset_index(drop=True)
    
    # Calculate delta features
    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]

    print("\n--- Raw Class Distribution ---")
    print(df[LABEL_COL].value_counts().to_string())

    # 2. Session Detection and Validation Snippet
    print("\n[+] Analysing capture sessions and features...")
    
    # Ensure chronological order
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    
    # Session detection: timestamp gap > 30 seconds or label changes starts a new session
    df["time_diff"] = df["timestamp"].diff()
    df["label_changed"] = df[LABEL_COL] != df[LABEL_COL].shift()
    df["new_session"] = (df["time_diff"] > 30.0) | (df["time_diff"].isna()) | df["label_changed"]
    df["session_id"] = df["new_session"].cumsum()

    # Print Session Info & Validation ranges
    sessions_info = []
    for sess_id, sess_df in df.groupby("session_id"):
        label = sess_df[LABEL_COL].iloc[0]
        count = len(sess_df)
        duration = sess_df["timestamp"].max() - sess_df["timestamp"].min()
        min_rate = sess_df["ewma_rate"].min()
        max_rate = sess_df["ewma_rate"].max()
        min_entropy = sess_df["entropy"].min()
        max_entropy = sess_df["entropy"].max()
        
        sessions_info.append({
            "Session ID": sess_id,
            "Label": label,
            "Rows": count,
            "Duration (s)": round(duration, 1),
            "Rate Range": f"{min_rate:.1f} - {max_rate:.1f}",
            "Entropy Range": f"{min_entropy:.2f} - {max_entropy:.2f}"
        })
    print("\n--- Detected Capture Sessions ---")
    print(pd.DataFrame(sessions_info).to_string(index=False))

    # Print overall feature ranges per class to evaluate overlap
    print("\n--- Feature Ranges Per Class (Overlap Check) ---")
    overlap_info = []
    for label in [0, 1, 2]:
        lbl_df = df[df[LABEL_COL] == label]
        if len(lbl_df) > 0:
            overlap_info.append({
                "Label": label,
                "Min Rate": lbl_df["ewma_rate"].min(),
                "Max Rate": lbl_df["ewma_rate"].max(),
                "Mean Rate": lbl_df["ewma_rate"].mean(),
                "Min Entropy": lbl_df["entropy"].min(),
                "Max Entropy": lbl_df["entropy"].max(),
                "Mean Entropy": lbl_df["entropy"].mean(),
                "Min Dominant IP Ratio": lbl_df["dominant_ip_ratio"].min(),
                "Max Dominant IP Ratio": lbl_df["dominant_ip_ratio"].max(),
                "Mean Dominant IP Ratio": lbl_df["dominant_ip_ratio"].mean()
            })
    print(pd.DataFrame(overlap_info).to_string(index=False))

    # 3. Split data by sessions
    print("\n[+] Partitioning data into train and test sets...")
    train_indices = []
    test_indices = []
    
    for label in [0, 1, 2]:
        label_df = df[df[LABEL_COL] == label]
        if len(label_df) == 0:
            continue
            
        unique_sessions = label_df["session_id"].unique()
        for sess_id in unique_sessions:
            sess_df = label_df[label_df["session_id"] == sess_id]
            split_idx = int(len(sess_df) * 0.8)
            
            train_indices.extend(sess_df.iloc[:split_idx].index)
            test_indices.extend(sess_df.iloc[split_idx:].index)
            print(f"[+] Label {label} Session {sess_id}: 80/20 chronological split.")

    X_train = df.loc[train_indices, FEATURE_COLS].copy()
    y_train = df.loc[train_indices, LABEL_COL].copy()
    
    X_test = df.loc[test_indices, FEATURE_COLS].copy()
    y_test = df.loc[test_indices, LABEL_COL].copy()

    # 4. Balance classes on the training split ONLY
    train_df = X_train.copy()
    train_df[LABEL_COL] = y_train.values
    
    df_normal = train_df[train_df[LABEL_COL] == 0]
    df_flash = train_df[train_df[LABEL_COL] == 1]
    df_ddos = train_df[train_df[LABEL_COL] == 2]
    
    if len(df_normal) > 0 and len(df_flash) > 0 and len(df_ddos) > 0:
        max_size = max(len(df_normal), len(df_flash), len(df_ddos))
        df_normal_upsampled = resample(df_normal, replace=True, n_samples=max_size, random_state=42)
        df_flash_upsampled = resample(df_flash, replace=True, n_samples=max_size, random_state=42)
        df_ddos_upsampled = resample(df_ddos, replace=True, n_samples=max_size, random_state=42)
        df_balanced = pd.concat([df_normal_upsampled, df_flash_upsampled, df_ddos_upsampled], ignore_index=True)
        
        X_train = df_balanced[FEATURE_COLS]
        y_train = df_balanced[LABEL_COL]
        print(f"[+] Balanced training set size: {len(X_train)} rows.")
    else:
        print("[!] Cannot balance training classes; one or more classes are missing.")
        
    print("\n--- Balanced Training Class Distribution ---")
    print(y_train.value_counts().to_string())

    if len(X_train) < 100:
        print("[-] Warning: Dataset is very small. Classification results may be unreliable.")

    # 6. Train Random Forest Model
    print(f"\n[+] Training Random Forest Classifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    print("[+] Model training complete.")
    
    # 7. Evaluate Model on Holdout Set
    print("\n[+] Evaluating model on holdout test set...")
    if len(X_test) > 0:
        y_pred = clf.predict(X_test)
        
        print("\n--- Classification Report ---")
        print(classification_report(y_test, y_pred, target_names=["Normal (0)", "Flash Crowd (1)", "DDoS (2)"], zero_division=0))
        
        print("\n--- Confusion Matrix ---")
        print(confusion_matrix(y_test, y_pred))
    else:
        print("[-] No test set available for evaluation.")
        
    # Feature Importances
    print("\n--- Feature Importances ---")
    importances = clf.feature_importances_
    for col, imp in sorted(zip(FEATURE_COLS, importances), key=lambda x: x[1], reverse=True):
        print(f"  {col:<20} : {imp:.4f}")
        
    # 8. Save Model
    print(f"\n[+] Saving trained model to: {MODEL_PATH}")
    joblib.dump(clf, MODEL_PATH)
    print("[+] Done!")

if __name__ == "__main__":
    main()
