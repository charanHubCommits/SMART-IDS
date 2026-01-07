#!/usr/bin/env python3
"""
Train Random Forest model for SmartIDS with proper preprocessing pipeline
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
import joblib
import os

print("="*70)
print("🚀 SmartIDS Model Training (tuned Random Forest)")
print("="*70)

# Training data files (same as original notebook)
training_files = [
    'data/Monday-WorkingHours.pcap_ISCX.csv',
    'data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'data/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'data/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
]

print("\n📂 Loading training data...")
sample_data = []
for file in training_files:
    if os.path.exists(file):
        print(f"   Loading {file.split('/')[-1]}...")
        df = pd.read_csv(file)
        sample_data.append(df)
        print(f"   ✓ Loaded {len(df):,} rows")

# Combine all data
print("\n🔄 Combining datasets...")
data = pd.concat(sample_data, ignore_index=True)
print(f"✓ Total rows: {len(data):,}")

# Clean column names
data.columns = data.columns.str.strip()
print(f"✓ Total columns: {len(data.columns)}")

# Map labels to binary (0 = BENIGN, 1 = ATTACK)
print("\n🏷️  Processing labels...")
label_counts = data['Label'].value_counts()
print("Original label distribution:")
for label, count in label_counts.items():
    print(f"   {label}: {count:,}")

data['Label'] = data['Label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
print("\nBinary label distribution:")
print(f"   BENIGN (0): {(data['Label'] == 0).sum():,}")
print(f"   ATTACK (1): {(data['Label'] == 1).sum():,}")

# Features and target
print("\n🔧 Preparing features...")
X = data.drop('Label', axis=1)
y = data['Label']

# Replace infinities and NaNs
print("   Handling infinite values...")
X.replace([np.inf, -np.inf], np.nan, inplace=True)
inf_count = X.isna().sum().sum()
print(f"   Replacing {inf_count:,} NaN/Inf values with 0")
X.fillna(0, inplace=True)

print(f"✓ Feature matrix shape: {X.shape}")
print(f"✓ Features: {X.shape[1]}")

# Scale features
print("\n📊 Scaling features with StandardScaler...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
print("✓ Scaling complete")

# Split data
print("\n✂️  Splitting data (80/20 train/test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
print(f"✓ Training set: {len(X_train):,} samples")
print(f"✓ Test set: {len(X_test):,} samples")

# Train Random Forest (tuned for better recall/precision)
print("\n🌲 Training Random Forest Classifier...")
rf_params = {
    'n_estimators': 300,
    'max_depth': None,
    'min_samples_split': 2,
    'min_samples_leaf': 1,
    'bootstrap': True,
    'class_weight': 'balanced',
    'n_jobs': -1,
    'random_state': 42,
    'verbose': 1
}
print(f"   Parameters: {rf_params}")
model = RandomForestClassifier(**rf_params)
model.fit(X_train, y_train)
print("✓ Training complete!")

# Evaluate
print("\n📈 Evaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
print(f"\n✅ Accuracy: {accuracy*100:.2f}%")
print(f"✅ F1-score: {f1*100:.2f}%")

print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))

print("\n🎯 Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"                Predicted")
print(f"              BENIGN  ATTACK")
print(f"Actual BENIGN  {cm[0][0]:6d}  {cm[0][1]:6d}")
print(f"       ATTACK  {cm[1][0]:6d}  {cm[1][1]:6d}")

# Calculate false positive rate
fp = cm[0][1]
tn = cm[0][0]
fpr = fp / (fp + tn)
print(f"\n⚠️  False Positive Rate: {fpr*100:.3f}%")

# Save model and scaler
print("\n💾 Saving model and scaler...")
os.makedirs('project_files/models', exist_ok=True)

model_path = 'project_files/models/random_forest.pkl'
scaler_path = 'project_files/models/scaler.pkl'

joblib.dump(model, model_path)
joblib.dump(scaler, scaler_path)

print(f"✓ Model saved to: {model_path}")
print(f"✓ Scaler saved to: {scaler_path}")

# Save feature names
feature_names_path = 'project_files/models/feature_names.pkl'
joblib.dump(X.columns.tolist(), feature_names_path)
print(f"✓ Feature names saved to: {feature_names_path}")

print("\n" + "="*70)
print("🎉 Training Complete!")
print("="*70)
print("\n✅ Model is ready for deployment in the web interface!")



