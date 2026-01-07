#!/usr/bin/env python3
"""
Train all ML models for SmartIDS with proper preprocessing pipeline
Trains: Random Forest, Decision Tree, XGBoost, Logistic Regression, SVM
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
import joblib
import os

# XGBoost import
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    print("⚠️  Warning: XGBoost not available. Install with: pip install xgboost")
    XGBOOST_AVAILABLE = False

print("="*70)
print("🚀 SmartIDS Model Training - All Models")
print("="*70)

# Training data files
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
    else:
        print(f"   ⚠️  File not found: {file}")

if not sample_data:
    print("\n❌ Error: No data files found! Please ensure CSV files are in the data/ directory.")
    exit(1)

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

# Create models directory
os.makedirs('project_files/models', exist_ok=True)

# Dictionary to store all models
models = {}
results = {}

# ============================================================================
# 1. Random Forest
# ============================================================================
print("\n" + "="*70)
print("🌲 Training Random Forest Classifier...")
print("="*70)
rf_params = {
    'n_estimators': 300,
    'max_depth': None,
    'min_samples_split': 2,
    'min_samples_leaf': 1,
    'bootstrap': True,
    'class_weight': 'balanced',
    'n_jobs': -1,
    'random_state': 42,
    'verbose': 0
}
rf_model = RandomForestClassifier(**rf_params)
rf_model.fit(X_train, y_train)
models['random_forest'] = rf_model

y_pred = rf_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
results['random_forest'] = {'accuracy': accuracy, 'f1': f1}
print(f"✅ Accuracy: {accuracy*100:.2f}%")
print(f"✅ F1-score: {f1*100:.2f}%")

# ============================================================================
# 2. Decision Tree
# ============================================================================
print("\n" + "="*70)
print("🌳 Training Decision Tree Classifier...")
print("="*70)
dt_model = DecisionTreeClassifier(random_state=42)
dt_model.fit(X_train, y_train)
models['decision_tree'] = dt_model

y_pred = dt_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
results['decision_tree'] = {'accuracy': accuracy, 'f1': f1}
print(f"✅ Accuracy: {accuracy*100:.2f}%")
print(f"✅ F1-score: {f1*100:.2f}%")

# ============================================================================
# 3. XGBoost
# ============================================================================
if XGBOOST_AVAILABLE:
    print("\n" + "="*70)
    print("🚀 Training XGBoost Classifier...")
    print("="*70)
    xgb_params = {
        'n_estimators': 100,
        'max_depth': 6,
        'learning_rate': 0.1,
        'eval_metric': 'logloss',
        'random_state': 42,
        'n_jobs': -1
    }
    xgb_model = XGBClassifier(**xgb_params)
    xgb_model.fit(X_train, y_train)
    models['xgboost'] = xgb_model

    y_pred = xgb_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    results['xgboost'] = {'accuracy': accuracy, 'f1': f1}
    print(f"✅ Accuracy: {accuracy*100:.2f}%")
    print(f"✅ F1-score: {f1*100:.2f}%")
else:
    print("\n⚠️  Skipping XGBoost (not available)")

# ============================================================================
# 4. Logistic Regression
# ============================================================================
print("\n" + "="*70)
print("📊 Training Logistic Regression Classifier...")
print("="*70)
lr_model = LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1)
lr_model.fit(X_train, y_train)
models['logistic_regression'] = lr_model

y_pred = lr_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
results['logistic_regression'] = {'accuracy': accuracy, 'f1': f1}
print(f"✅ Accuracy: {accuracy*100:.2f}%")
print(f"✅ F1-score: {f1*100:.2f}%")

# ============================================================================
# 5. SVM (using linear kernel for faster training)
# ============================================================================
print("\n" + "="*70)
print("🔷 Training SVM Classifier (Linear Kernel)...")
print("="*70)
print("   Note: SVM training may take longer...")
svm_model = SVC(kernel='linear', probability=True, random_state=42)
svm_model.fit(X_train, y_train)
models['svm'] = svm_model

y_pred = svm_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
results['svm'] = {'accuracy': accuracy, 'f1': f1}
print(f"✅ Accuracy: {accuracy*100:.2f}%")
print(f"✅ F1-score: {f1*100:.2f}%")

# ============================================================================
# Save all models
# ============================================================================
print("\n" + "="*70)
print("💾 Saving all models...")
print("="*70)

# Save scaler (shared across all models)
scaler_path = 'project_files/models/scaler.pkl'
joblib.dump(scaler, scaler_path)
print(f"✓ Scaler saved to: {scaler_path}")

# Save feature names
feature_names_path = 'project_files/models/feature_names.pkl'
joblib.dump(X.columns.tolist(), feature_names_path)
print(f"✓ Feature names saved to: {feature_names_path}")

# Save each model
for model_name, model in models.items():
    model_path = f'project_files/models/{model_name}.pkl'
    joblib.dump(model, model_path)
    acc = results[model_name]['accuracy'] * 100
    print(f"✓ {model_name.replace('_', ' ').title()} saved to: {model_path} (Accuracy: {acc:.2f}%)")

# ============================================================================
# Summary
# ============================================================================
print("\n" + "="*70)
print("📊 Training Summary")
print("="*70)
print(f"{'Model':<25} {'Accuracy':<15} {'F1-Score':<15}")
print("-" * 70)
for model_name, metrics in results.items():
    print(f"{model_name.replace('_', ' ').title():<25} {metrics['accuracy']*100:>6.2f}%       {metrics['f1']*100:>6.2f}%")

print("\n" + "="*70)
print("🎉 All Models Trained Successfully!")
print("="*70)
print("\n✅ Models are ready for deployment in the web interface!")
print("📁 Models saved in: project_files/models/")
print("\n🚀 Run 'python app.py' to start the web dashboard!")
