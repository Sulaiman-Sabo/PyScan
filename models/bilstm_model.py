"""
PyScan BiLSTM-Attention Neural Network Model Architecture (PyTorch)

Combines Word Embeddings, 2-layer Bidirectional LSTM, Self-Attention Mechanism,
and a Dropout-regularized Classification Head.

Author: PyScan Project -- BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import json
import os
from typing import Dict, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


class AttentionLayer(nn.Module):
    """
    Self-Attention Mechanism for token importance scoring in code sequences.
    """

    def __init__(self, hidden_dim: int) -> None:
        super().__init__()
        self.attn_weights = nn.Linear(hidden_dim, 1, bias=False)

    def forward(self, lstm_output: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        attn_scores = self.attn_weights(lstm_output).squeeze(-1)  # (batch_size, seq_len)
        attn_probs = F.softmax(attn_scores, dim=1)  # (batch_size, seq_len)
        context_vector = torch.bmm(attn_probs.unsqueeze(1), lstm_output).squeeze(1)  # (batch_size, hidden_dim)
        return context_vector, attn_probs


class PyScanBiLSTMAttentionEnhanced(nn.Module):
    """
    BiLSTM-Attention Deep Learning Vulnerability Classifier.
    """

    def __init__(
        self,
        vocab_size: int = 15000,
        embedding_dim: int = 128,
        hidden_dim: int = 64,
        num_layers: int = 2,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()

        self.vocab_size = vocab_size
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim

        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embedding_dim,
            padding_idx=0,
        )

        self.bilstm = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        self.layer_norm = nn.LayerNorm(hidden_dim * 2)
        self.attention = AttentionLayer(hidden_dim * 2)

        self.fc1 = nn.Linear(hidden_dim * 2, 64)
        self.dropout = nn.Dropout(dropout)
        self.fc_out = nn.Linear(64, 1)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        embedded = self.embedding(x)
        lstm_out, _ = self.bilstm(embedded)
        lstm_out = self.layer_norm(lstm_out)

        context, attn_weights = self.attention(lstm_out)

        dense = F.relu(self.fc1(context))
        dense = self.dropout(dense)
        logits = self.fc_out(dense)
        return logits, attn_weights


if __name__ == "__main__":
    model = PyScanBiLSTMAttentionEnhanced()
    dummy_input = torch.randint(0, 1000, (8, 200))
    logits, weights = model(dummy_input)
    print("Model initialized successfully!")
    print(f"Input shape: {dummy_input.shape}")
    print(f"Logits output shape: {logits.shape}")
    print(f"Attention weights shape: {weights.shape}")
