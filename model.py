"""
BiLSTM with Attention Model (Section 3.5.3)
Deep learning architecture for Python vulnerability detection
"""
import torch
import torch.nn as nn
import numpy as np

from config import MODEL_CONFIG


class AttentionLayer(nn.Module):
    """
    Additive Attention Mechanism (Bahdanau et al. 2015)
    Computes attention weights for each token position
    """
    def __init__(self, input_dim, attention_dim):
        super(AttentionLayer, self).__init__()
        self.W = nn.Linear(input_dim, attention_dim)
        self.b = nn.Parameter(torch.zeros(attention_dim))
        self.v = nn.Linear(attention_dim, 1, bias=False)
        
    def forward(self, inputs, return_attention=False):
        # inputs shape: (batch, seq_len, input_dim)
        score = torch.tanh(self.W(inputs) + self.b)
        attention_weights = torch.softmax(self.v(score), dim=1)
        context = torch.sum(inputs * attention_weights, dim=1)
        
        if return_attention:
            return context, attention_weights
        return context


class BiLSTMAttentionModel(nn.Module):
    """
    BiLSTM with Attention model architecture
    """
    def __init__(self, vocab_size, embedding_dim=128, max_len=200,
                 bilstm_units_1=128, bilstm_units_2=64):
        super(BiLSTMAttentionModel, self).__init__()
        
        self.max_len = max_len
        self.bilstm_units_1 = bilstm_units_1
        self.bilstm_units_2 = bilstm_units_2
        
        # Embedding Layer
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embedding_dim,
            padding_idx=0
        )
        
        # First BiLSTM Layer
        self.bilstm_1 = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=bilstm_units_1,
            bidirectional=True,
            batch_first=True,
            dropout=0.2
        )
        
        # Attention Mechanism
        self.attention = AttentionLayer(
            input_dim=bilstm_units_1 * 2,  # *2 for bidirectional
            attention_dim=MODEL_CONFIG['attention_dim']
        )
        
        # Second BiLSTM Layer
        self.bilstm_2 = nn.LSTM(
            input_size=bilstm_units_1 * 2 + bilstm_units_1 * 2,  # merged input
            hidden_size=bilstm_units_2,
            bidirectional=True,
            batch_first=True,
            dropout=0.2
        )
        
        # Dense Layers
        self.dense = nn.Linear(bilstm_units_2 * 2, 128)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(MODEL_CONFIG['dropout_rate'])
        self.output_layer = nn.Linear(128, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x, return_attention=False):
        # Embedding
        x = self.embedding(x)
        
        # First BiLSTM
        bilstm_1_out, _ = self.bilstm_1(x)
        
        # Attention
        if return_attention:
            context, attention_weights = self.attention(bilstm_1_out, return_attention=True)
        else:
            context = self.attention(bilstm_1_out)
            attention_weights = None
        
        # Repeat context and merge
        context_repeated = context.unsqueeze(1).repeat(1, self.max_len, 1)
        merged = torch.cat([bilstm_1_out, context_repeated], dim=2)
        
        # Second BiLSTM
        bilstm_2_out, _ = self.bilstm_2(merged)
        bilstm_2_out = bilstm_2_out[:, -1, :]  # Take last output
        
        # Dense layers
        dense_out = self.relu(self.dense(bilstm_2_out))
        dropout_out = self.dropout(dense_out)
        output = self.sigmoid(self.output_layer(dropout_out))
        
        if return_attention:
            return output, attention_weights
        return output


def build_bilstm_attention_model(vocab_size: int, embedding_dim: int = 128,
                                  max_len: int = 200,
                                  bilstm_units_1: int = 128,
                                  bilstm_units_2: int = 64) -> BiLSTMAttentionModel:
    """
    Build BiLSTM with Attention model architecture
    """
    model = BiLSTMAttentionModel(
        vocab_size=vocab_size,
        embedding_dim=embedding_dim,
        max_len=max_len,
        bilstm_units_1=bilstm_units_1,
        bilstm_units_2=bilstm_units_2
    )
    return model


class VulnerabilityDetector:
    """Wrapper class for the complete detection pipeline"""
    
    def __init__(self, model: BiLSTMAttentionModel = None, preprocessor=None):
        self.model = model
        self.preprocessor = preprocessor
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        if model is not None:
            self.model.to(self.device)
            self.model.eval()
    
    def predict(self, code: str, return_attention: bool = True):
        """Predict vulnerability for a single code sample"""
        if self.preprocessor is None or self.model is None:
            raise ValueError("Model and preprocessor must be loaded first")
        
        sequence = self.preprocessor.transform(code)
        X = torch.tensor([sequence], dtype=torch.long).to(self.device)
        
        with torch.no_grad():
            if return_attention:
                prediction, attention_weights = self.model(X, return_attention=True)
                prediction = prediction[0][0].item()
                attention_weights = attention_weights[0].cpu().numpy().flatten()
            else:
                prediction = self.model(X)[0][0].item()
                attention_weights = None
        
        return {
            'is_vulnerable': prediction > 0.5,
            'confidence': float(prediction),
            'attention_weights': attention_weights
        }
    
    def load_model(self, model_path: str):
        """Load a saved model"""
        self.model = torch.load(model_path, map_location=self.device)
        self.model.eval()
    
    def save_model(self, model_path: str):
        """Save the model"""
        torch.save(self.model, model_path)


if __name__ == '__main__':
    print("Building BiLSTM + Attention model (PyTorch)...")
    test_model = build_bilstm_attention_model(
        vocab_size=1000,
        embedding_dim=64,
        max_len=50,
        bilstm_units_1=32,
        bilstm_units_2=16
    )
    
    # Print model architecture
    print(test_model)
    
    # Count parameters
    total_params = sum(p.numel() for p in test_model.parameters())
    trainable_params = sum(p.numel() for p in test_model.parameters() if p.requires_grad)
    print(f"\nTotal parameters: {total_params:,}")
    print(f"Trainable parameters: {trainable_params:,}")
    
    # Test forward pass
    print("\nTesting forward pass...")
    dummy_input = torch.randint(0, 1000, (2, 50))  # batch_size=2, seq_len=50
    output = test_model(dummy_input)
    print(f"Output shape: {output.shape}")
    
    output_with_attention, attention = test_model(dummy_input, return_attention=True)
    print(f"Output with attention shape: {output_with_attention.shape}")
    print(f"Attention weights shape: {attention.shape}")