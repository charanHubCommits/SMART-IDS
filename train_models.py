import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier
from sklearn.linear_model import LogisticRegression

print("Loading data for retraining to fix missing attacks...")

data_dir = 'data'
# We will use all available ISCX files to make sure all attacks are included
csv_files = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv'
]

# We don't want to load all 3 million rows (memory issues)
# We will selectively sample: all attacks + balanced benign
dfs = []
for file in csv_files:
    path = os.path.join(data_dir, file)
    if os.path.exists(path):
        print(f"Reading {file}...")
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        
        # Handle duplicate column names exactly like evaluation script
        cols = df.columns.tolist()
        new_cols = []
        seen = {}
        for c in cols:
            if c in seen:
                seen[c] += 1
                new_cols.append(f"{c}.{seen[c]}")
            else:
                seen[c] = 0
                new_cols.append(c)
        df.columns = new_cols
        
        # Take all attacks, but limit benign to keep dataset balanced
        attacks = df[df['Label'] != 'BENIGN']
        benigns = df[df['Label'] == 'BENIGN']
        
        # Take up to 15,000 benigns per file, and all attacks (up to 30,000 per type)
        if len(benigns) > 15000:
            benigns = benigns.sample(15000, random_state=42)
            
        dfs.append(attacks)
        dfs.append(benigns)

data = pd.concat(dfs, ignore_index=True)
print(f"\nCombined dataset size: {data.shape}")
print("Label distribution:")
print(data['Label'].value_counts())

X = data.drop('Label', axis=1)
y = data['Label']

# Clean data
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

# Save feature names so evaluation works properly
feature_names = X.columns.tolist()
joblib.dump(feature_names, 'project_files/models/feature_names.pkl')
print(f"Saved {len(feature_names)} feature names")

# Fit scaler
print("\nScaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, 'project_files/models/scaler.pkl')

# Fit label encoder
print("Encoding labels...")
le = LabelEncoder()
# Ensure BENIGN gets mapped to 0
labels_unique = y.unique()
if 'BENIGN' in labels_unique:
    classes = ['BENIGN'] + [c for c in labels_unique if c != 'BENIGN']
    le.classes_ = np.array(classes)
    y_encoded = le.transform(y)
else:
    y_encoded = le.fit_transform(y)
joblib.dump(le, 'project_files/models/label_encoder.pkl')

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)
print("\nTraining models...")

# 1. Decision Tree
print("1/4: Training Decision Tree...")
dt = DecisionTreeClassifier(random_state=42)
dt.fit(X_train, y_train)
joblib.dump(dt, 'project_files/models/decision_tree.pkl')

# 2. Random Forest
print("2/4: Training Random Forest...")
rf = RandomForestClassifier(n_estimators=50, max_depth=None, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
joblib.dump(rf, 'project_files/models/random_forest.pkl')

# 3. XGBoost
print("3/4: Training XGBoost...")
xgb = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, use_label_encoder=False, eval_metric='mlogloss', random_state=42, n_jobs=-1)
xgb.fit(X_train, y_train)
joblib.dump(xgb, 'project_files/models/xgboost.pkl')

# 4. Logistic Regression
print("4/4: Training Logistic Regression...")
lr = LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1)
lr.fit(X_train, y_train)
joblib.dump(lr, 'project_files/models/logistic_regression.pkl')

print("\nSUCCESS! All models retrained and saved. Missing attacks fixed!")
