# bert_model.py - Updated version
import pandas as pd
import torch
from transformers import BertTokenizer, BertForSequenceClassification
from torch.optim import AdamW  # Import AdamW from torch.optim instead
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np
import os

print("Starting BERT model training...")

# Load dataset
print("Loading dataset...")
df = pd.read_csv('data/emails.csv')
X = df['Email Text'].fillna('')
y = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})

# Take a subset for BERT training to reduce time (optional)
# Remove this if you want to train on the full dataset
sample_size = min(5000, len(df))  # Limit to 5000 samples for faster training
if len(df) > sample_size:
    print(f"Using {sample_size} samples for BERT training (out of {len(df)})")
    indices = np.random.choice(len(df), sample_size, replace=False)
    X = X.iloc[indices]
    y = y.iloc[indices]

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Create output directory
os.makedirs('backend/bert_model', exist_ok=True)

# Check for GPU
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {device}")

# Load BERT tokenizer and model
print("Loading BERT model...")
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
model.to(device)

# Tokenize emails
def tokenize_emails(texts, max_length=128):
    return tokenizer(
        texts.tolist(),
        padding='max_length',
        truncation=True,
        max_length=max_length,
        return_tensors='pt'
    )

print("Tokenizing emails...")
# Use a smaller max_length to reduce memory usage
train_encodings = tokenize_emails(X_train, max_length=128)
test_encodings = tokenize_emails(X_test, max_length=128)

train_dataset = TensorDataset(
    train_encodings['input_ids'],
    train_encodings['attention_mask'],
    torch.tensor(y_train.values)
)

test_dataset = TensorDataset(
    test_encodings['input_ids'],
    test_encodings['attention_mask'],
    torch.tensor(y_test.values)
)

# Create data loaders with smaller batch size
print("Creating data loaders...")
batch_size = 16 if torch.cuda.is_available() else 8
train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=batch_size)

# Training settings - use AdamW from torch.optim
optimizer = AdamW(model.parameters(), lr=5e-5)

# Training loop
print("Starting training...")
num_epochs = 3
for epoch in range(num_epochs):
    model.train()
    total_loss = 0
    for batch in train_loader:
        input_ids, attention_mask, labels = [b.to(device) for b in batch]
        
        optimizer.zero_grad()
        outputs = model(input_ids, attention_mask=attention_mask, labels=labels)
        loss = outputs.loss
        total_loss += loss.item()
        loss.backward()
        optimizer.step()
    
    avg_loss = total_loss / len(train_loader)
    print(f"Epoch {epoch+1}/{num_epochs}, Average Loss: {avg_loss:.4f}")
    
    # Evaluation
    model.eval()
    predictions = []
    true_labels = []
    
    for batch in test_loader:
        input_ids, attention_mask, labels = [b.to(device) for b in batch]
        
        with torch.no_grad():
            outputs = model(input_ids, attention_mask=attention_mask)
            
        logits = outputs.logits
        pred = torch.argmax(logits, dim=1).cpu().numpy()
        true = labels.cpu().numpy()
        
        predictions.extend(pred)
        true_labels.extend(true)
    
    acc = accuracy_score(true_labels, predictions)
    print(f"Accuracy: {acc:.4f}")
    print("Classification Report:\n", classification_report(true_labels, predictions))

# Save the model
print("Saving BERT model...")
model_save_path = 'backend/bert_model'
model.save_pretrained(model_save_path)
tokenizer.save_pretrained(model_save_path)
print(f"BERT model saved to {model_save_path}")

print("BERT training complete!")