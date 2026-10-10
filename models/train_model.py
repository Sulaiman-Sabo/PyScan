"""
PyScan Fast BiLSTM-Attention Deep Learning Model Training Pipeline

Trains PyScanBiLSTMAttentionEnhanced on CPU efficiently with batch size 128,
class weighting, and threshold calibration.

Author: SULAIMAN SABO -- PyScan Project -- BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import json
import os
import sys
import time
from typing import Dict, Tuple

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from torch.utils.data import DataLoader, TensorDataset

# Add project root to sys.path so 'models' module can be found
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
from models.bilstm_model import PyScanBiLSTMAttentionEnhanced


def train_pyscan_model(
    data_dir: str = "combined_dataset/processed",
    output_model_path: str = "models/pyscan_bilstm_model.pt",
    vocab_path: str = "models/tokenizer_config.json",
    epochs: int = 10,
    batch_size: int = 128,
    learning_rate: float = 0.002,
) -> Dict[str, float]:
    print("==================================================================")
    print(" PyScan Fast Deep Learning Model Training Pipeline")
    print("==================================================================")

    # Convert paths to absolute paths based on project root
    data_dir = os.path.join(project_root, data_dir)
    output_model_path = os.path.join(project_root, output_model_path)
    vocab_path = os.path.join(project_root, vocab_path)

    # 1. Load Datasets
    print(f"[*] Loading processed datasets from '{data_dir}'...")
    X_train = np.load(os.path.join(data_dir, "X_train.npy"))
    y_train = np.load(os.path.join(data_dir, "y_train.npy"))
    X_val = np.load(os.path.join(data_dir, "X_val.npy"))
    y_val = np.load(os.path.join(data_dir, "y_val.npy"))
    X_test = np.load(os.path.join(data_dir, "X_test.npy"))
    y_test = np.load(os.path.join(data_dir, "y_test.npy"))

    num_vulnerable = int(np.sum(y_train == 1))
    num_safe = int(np.sum(y_train == 0))
    pos_weight_val = num_safe / float(num_vulnerable)

    print(f"    - Train Samples: {X_train.shape[0]:,} | Val: {X_val.shape[0]:,} | Test: {X_test.shape[0]:,}")
    print(f"    - Class Balance Weighting (pos_weight): {pos_weight_val:.3f}")

    with open(vocab_path, "r", encoding="utf-8") as f:
        vocab = json.load(f)
    
    # Ensure vocabulary size is large enough for all token indices in the dataset to prevent IndexError
    vocab_size = max(len(vocab) + 100, int(X_train.max()) + 1, int(X_val.max()) + 1, int(X_test.max()) + 1)

    train_dataset = TensorDataset(torch.tensor(X_train, dtype=torch.long), torch.tensor(y_train, dtype=torch.float32))
    val_dataset = TensorDataset(torch.tensor(X_val, dtype=torch.long), torch.tensor(y_val, dtype=torch.float32))
    test_dataset = TensorDataset(torch.tensor(X_test, dtype=torch.long), torch.tensor(y_test, dtype=torch.float32))

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training Device: {device}")

    model = PyScanBiLSTMAttentionEnhanced(
        vocab_size=vocab_size,
        embedding_dim=128,
        hidden_dim=64,
        num_layers=2,
        dropout=0.3,
    ).to(device)

    pos_weight_tensor = torch.tensor([pos_weight_val * 1.2], device=device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight_tensor)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)

    best_val_f1 = 0.0
    best_val_loss = float("inf")

    print("\n[*] Starting Neural Network Training...")
    start_time = time.time()

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        train_preds, train_targets = [], []

        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            optimizer.zero_grad()

            logits, _ = model(batch_x)
            loss = criterion(logits.squeeze(-1), batch_y)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            train_loss += loss.item() * batch_x.size(0)
            probs = torch.sigmoid(logits.squeeze(-1)).detach().cpu().numpy()
            train_preds.extend(probs)
            train_targets.extend(batch_y.cpu().numpy())

        train_loss /= len(train_dataset)
        train_acc = accuracy_score(train_targets, (np.array(train_preds) >= 0.5).astype(int))

        # Validation Phase
        model.eval()
        val_loss = 0.0
        val_preds, val_targets = [], []

        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                logits, _ = model(batch_x)
                loss = criterion(logits.squeeze(-1), batch_y)

                val_loss += loss.item() * batch_x.size(0)
                probs = torch.sigmoid(logits.squeeze(-1)).cpu().numpy()
                val_preds.extend(probs)
                val_targets.extend(batch_y.cpu().numpy())

        val_loss /= len(val_dataset)
        val_preds_arr = np.array(val_preds)
        val_targets_arr = np.array(val_targets)

        val_acc = accuracy_score(val_targets_arr, (val_preds_arr >= 0.5).astype(int))
        val_f1 = f1_score(val_targets_arr, (val_preds_arr >= 0.5).astype(int))

        print(f"    Epoch {epoch:02d}/{epochs:02d} | "
              f"Train Loss: {train_loss:.4f} - Acc: {train_acc*100:.2f}% | "
              f"Val Loss: {val_loss:.4f} - Acc: {val_acc*100:.2f}% - F1: {val_f1:.4f}")

        if val_f1 > best_val_f1 or (val_f1 == best_val_f1 and val_loss < best_val_loss):
            best_val_f1 = val_f1
            best_val_loss = val_loss
            os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
            torch.save(model.state_dict(), output_model_path)

    training_time = time.time() - start_time
    print(f"[+] Model Training Completed in {training_time:.1f} seconds.")

    # 5. Threshold Calibration on Validation Set
    print("\n[*] Calibrating Prediction Threshold for Optimal F1 & Recall...")
    model.load_state_dict(torch.load(output_model_path, map_location=device))
    model.eval()

    val_preds, val_targets = [], []
    with torch.no_grad():
        for batch_x, batch_y in val_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            logits, _ = model(batch_x)
            probs = torch.sigmoid(logits.squeeze(-1)).cpu().numpy()
            val_preds.extend(probs)
            val_targets.extend(batch_y.cpu().numpy())

    val_preds_arr = np.array(val_preds)
    val_targets_arr = np.array(val_targets)

    best_thresh = 0.5
    best_thresh_f1 = 0.0
    for thresh in np.arange(0.30, 0.70, 0.02):
        score = f1_score(val_targets_arr, (val_preds_arr >= thresh).astype(int))
        if score > best_thresh_f1:
            best_thresh_f1 = score
            best_thresh = thresh

    print(f"[+] Calibrated Decision Threshold: {best_thresh:.2f} (Val F1: {best_thresh_f1:.4f})")

    # 6. Final Evaluation on TEST SET
    print("\n[*] Evaluating Calibrated Model on Unseen TEST SET...")
    test_preds, test_targets = [], []
    with torch.no_grad():
        for batch_x, batch_y in test_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            logits, _ = model(batch_x)
            probs = torch.sigmoid(logits.squeeze(-1)).cpu().numpy()
            test_preds.extend(probs)
            test_targets.extend(batch_y.cpu().numpy())

    test_preds_arr = np.array(test_preds)
    test_targets_arr = np.array(test_targets)
    test_preds_binary = (test_preds_arr >= best_thresh).astype(int)

    test_acc = accuracy_score(test_targets_arr, test_preds_binary)
    test_prec = precision_score(test_targets_arr, test_preds_binary)
    test_rec = recall_score(test_targets_arr, test_preds_binary)
    test_f1 = f1_score(test_targets_arr, test_preds_binary)
    test_auc = roc_auc_score(test_targets_arr, test_preds_arr)

    print("==================================================================")
    print(" Final Model Performance Metrics on TEST SET:")
    print("==================================================================")
    print(f"  • Test Accuracy : {test_acc*100:.2f}%")
    print(f"  • Precision     : {test_prec*100:.2f}%  (Low False Positives)")
    print(f"  • Recall        : {test_rec*100:.2f}%  (High Sensitivity / Low Negligence)")
    print(f"  • F1-Score      : {test_f1:.4f}")
    print(f"  • ROC-AUC Score : {test_auc:.4f}")
    print("==================================================================")

    metrics = {
        "calibrated_threshold": float(best_thresh),
        "test_accuracy": float(test_acc),
        "test_precision": float(test_prec),
        "test_recall": float(test_rec),
        "test_f1": float(test_f1),
        "test_auc": float(test_auc),
        "training_time_seconds": float(training_time),
    }

    with open("models/training_report.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return metrics


if __name__ == "__main__":
    train_pyscan_model()
