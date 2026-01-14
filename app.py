from flask import Flask, render_template, jsonify, request, make_response
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
import json
import os
from sklearn.preprocessing import StandardScaler
from collections import Counter

app = Flask(__name__)

# Disable caching for static files (important for development)
@app.after_request
def add_header(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Load the trained models and scaler(s)
models = {}
scalers = {}
feature_names = []
ENSEMBLE_CONF_THRESHOLD = 0.6

def load_models_and_scalers():
    """Load available models and shared scaler from disk."""
    # Known model filenames -> key
    candidate_models = {
        'random_forest': 'project_files/models/random_forest.pkl',
        'svm': 'project_files/models/svm.pkl',
        'decision_tree': 'project_files/models/decision_tree.pkl',
        'xgboost': 'project_files/models/xgboost.pkl',
        'logistic_regression': 'project_files/models/logistic_regression.pkl',
    }

    available = 0
    for key, path in candidate_models.items():
        if os.path.exists(path):
            try:
                models[key] = joblib.load(path)
                available += 1
                print(f"Loaded model: {key} ({path})")
            except Exception as e:
                models[key] = None
                print(f"Failed to load {key} from {path}: {e}")
        else:
            models[key] = None

    # Shared scaler (applied to all models that expect it)
    scaler_path = 'project_files/models/scaler.pkl'
    if os.path.exists(scaler_path):
        try:
            shared_scaler = joblib.load(scaler_path)
            for key in models.keys():
                scalers[key] = shared_scaler
            print("Scaler loaded")
        except Exception as e:
            print(f"Warning: Failed to load scaler: {e}")
    else:
        print("Warning: Scaler not found. Please run training first.")
    
    # Load feature names if available (used to align incoming features)
    feature_path = 'project_files/models/feature_names.pkl'
    global feature_names
    if os.path.exists(feature_path):
        try:
            feature_names = joblib.load(feature_path)
            print(f"Loaded {len(feature_names)} feature names")
        except Exception as e:
            print(f"Warning: Failed to load feature names: {e}")

    if available == 0:
        print("Error: No models found. Please train or copy models into project_files/models/")

# Load models on startup
load_models_and_scalers()

# Load sample data to get feature names and for simulation
# Using a mix of benign and attack data for realistic simulation
# These are files NOT used for training
data_files = [
    'data/Tuesday-WorkingHours.pcap_ISCX.csv',  # Mostly benign
    'data/Wednesday-workingHours.pcap_ISCX.csv',  # Mixed traffic
    'data/Friday-WorkingHours-Morning.pcap_ISCX.csv'  # Contains some attacks
]

# Add attack samples for realistic simulation
# Using attack types the model was TRAINED on (for better detection)
attack_sim_files = [
    'data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',  # DDoS attacks
    'data/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',  # Web attacks
]

print("Loading sample data for simulation...")
sample_data = []
all_columns = None
feature_columns = None

# First pass: determine column schema
first_file = data_files[0] if data_files else None
if first_file and os.path.exists(first_file):
    temp_df = pd.read_csv(first_file, nrows=1)
    temp_df.columns = temp_df.columns.str.strip()
    all_columns = temp_df.columns.tolist()
    # Store feature columns (without Label)
    if 'Label' in all_columns:
        feature_columns = [col for col in all_columns if col != 'Label']
    print(f"Using column schema from {first_file.split('/')[-1]} ({len(all_columns)} columns)")

# Load benign data
for file in data_files:
    if os.path.exists(file):
        df = pd.read_csv(file, nrows=1000)  # Load limited rows for simulation
        df.columns = df.columns.str.strip()
        # Ensure columns match
        if all_columns is not None:
            # Reorder and select only the columns we need
            df = df[all_columns]
        sample_data.append(df)

# Add attack samples for more interesting simulation
print("Loading attack samples for simulation...")
for file in attack_sim_files:
    if os.path.exists(file):
        try:
            # Load LOTS of rows to ensure we get actual attacks (DDoS file has attacks later)
            df = pd.read_csv(file, nrows=100000)  # Load 100k rows to ensure attacks
            df.columns = df.columns.str.strip()
            if 'Label' in df.columns:
                # Keep only actual attacks - get MORE for better demo
                attack_df = df[df['Label'] != 'BENIGN'].head(300)  # Get 300 from each file
                if len(attack_df) > 0:
                    # Ensure columns match (including Label column)
                    if all_columns is not None:
                        # Make sure attack_df has all the required columns
                        missing_cols = set(all_columns) - set(attack_df.columns)
                        if not missing_cols:
                            attack_df = attack_df[all_columns]
                            sample_data.append(attack_df)
                            print(f"  Added {len(attack_df)} attack samples from {file.split('/')[-1]}")
                        else:
                            print(f"  Skipped {file.split('/')[-1]} - missing columns: {missing_cols}")
                    else:
                        sample_data.append(attack_df)
                        print(f"  Added {len(attack_df)} attack samples from {file.split('/')[-1]}")
        except Exception as e:
            print(f"  Error loading {file.split('/')[-1]}: {str(e)}")

if sample_data:
    simulation_data = pd.concat(sample_data, ignore_index=True)
    # Columns should already be aligned, but strip again just in case
    simulation_data.columns = simulation_data.columns.str.strip()
    
    # Prepare features
    if 'Label' in simulation_data.columns:
        X_sim = simulation_data.drop('Label', axis=1)
        # Convert labels to numeric (0 for BENIGN, 1 for anything else)
        y_sim = simulation_data['Label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
    else:
        X_sim = simulation_data
        y_sim = None
    
    # Handle inf and nan
    X_sim.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_sim.fillna(0, inplace=True)
    
    feature_names = X_sim.columns.tolist()
    print(f"Loaded {len(simulation_data)} samples for simulation")
else:
    X_sim = None
    y_sim = None
    feature_names = []

# Statistics for dashboard
stats = {
    'total_packets': 0,
    'benign_count': 0,
    'attack_count': 0,
    'last_prediction': None
}

@app.route('/')
def index():
    """Main dashboard page"""
    available_models = {
        'random_forest': models.get('random_forest') is not None,
        'svm': models.get('svm') is not None,
        'decision_tree': models.get('decision_tree') is not None,
        'xgboost': models.get('xgboost') is not None,
        'logistic_regression': models.get('logistic_regression') is not None
    }
    return render_template('index.html', models=available_models)

@app.route('/test')
def test_page():
    """Test page to verify API without cache issues"""
    return render_template('test.html')

@app.route('/api/predict', methods=['POST'])
def predict():
    """Make prediction on single packet"""
    try:
        data = request.json
        model_name = data.get('model', 'auto')
        
        # Get features from request
        features = data.get('features', [])
        if not features:
            return jsonify({'error': 'No features provided'}), 400
        
        # Helper to run a single model
        def run_model(name, feats):
            model = models.get(name)
            if model is None:
                return None
            arr = np.array(feats).reshape(1, -1)
            if scalers.get(name) is not None:
                arr = scalers[name].transform(arr)
            pred = model.predict(arr)[0]
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(arr)[0]
                conf = float(max(proba))
            else:
                conf = 1.0
            return {
                'model': name,
                'prediction': int(pred),
                'label': 'BENIGN' if pred == 0 else 'ATTACK',
                'confidence': conf
            }

        available_models = [k for k, v in models.items() if v is not None]
        if not available_models:
            return jsonify({'error': 'No models available'}), 400

        if model_name == 'auto':
            # Evaluate across all available models and do ensemble voting
            results = [run_model(m, features) for m in available_models]
            results = [r for r in results if r is not None]
            if not results:
                return jsonify({'error': 'No models available'}), 400

            # Confidence-thresholded voting
            high_conf = [r for r in results if r['confidence'] >= ENSEMBLE_CONF_THRESHOLD]
            vote_pool = high_conf if high_conf else results

            # Majority vote on prediction
            preds = [r['prediction'] for r in vote_pool]
            counts = Counter(preds)
            top_pred = counts.most_common(1)[0][0]

            # Among models voting top_pred, pick highest confidence for reporting
            top_models = [r for r in vote_pool if r['prediction'] == top_pred]
            best = max(top_models, key=lambda r: r['confidence'])

            response = {
                'prediction': int(top_pred),
                'label': 'BENIGN' if top_pred == 0 else 'ATTACK',
                'confidence': float(best['confidence']),
                'model_selected': 'ensemble',
                'evaluated_models': [
                    {'model': r['model'], 'confidence': r['confidence'], 'prediction': r['prediction']}
                    for r in results
                ],
                'timestamp': datetime.now().isoformat()
            }
            return jsonify(response)
        else:
            if models.get(model_name) is None:
                return jsonify({'error': f'Model {model_name} not available'}), 400
            result = run_model(model_name, features)
            result['timestamp'] = datetime.now().isoformat()
            result['model_selected'] = model_name
            return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/simulate', methods=['POST'])
def simulate():
    """Simulate real-time traffic"""
    try:
        data = request.json
        model_name = data.get('model', 'auto')
        num_packets = data.get('num_packets', 1)
        
        available_models = [k for k, v in models.items() if v is not None]
        if not available_models:
            return jsonify({'error': 'No models available'}), 400
        if model_name != 'auto' and models.get(model_name) is None:
            return jsonify({'error': f'Model {model_name} not available'}), 400
        if X_sim is None:
            return jsonify({'error': 'No simulation data available'}), 400
        
        # Get random mix of benign and attack samples
        # Use a tuned attack probability to avoid overly attack-heavy streams
        attack_probability = 0.3  # 30% attacks in simulation
        if y_sim is not None:
            attack_indices = y_sim[y_sim == 1].index.tolist()
            benign_indices = y_sim[y_sim == 0].index.tolist()
            
            # For each packet, randomly decide if it's attack or benign (50% probability)
            indices = []
            for _ in range(num_packets):
                if np.random.random() < attack_probability and len(attack_indices) > 0:
                    # Select an attack
                    idx = np.random.choice(attack_indices)
                    indices.append(idx)
                else:
                    # Select benign
                    idx = np.random.choice(benign_indices)
                    indices.append(idx)
            
            indices = np.array(indices)
        else:
            # Fallback to random if no labels available
            indices = np.random.choice(len(X_sim), size=min(num_packets, len(X_sim)), replace=False)
        
        samples = X_sim.iloc[indices]
        
        def predict_with_model(name, row_array):
            model = models.get(name)
            arr = row_array.reshape(1, -1)
            if scalers.get(name) is not None:
                arr = scalers[name].transform(arr)
            pred = model.predict(arr)[0]
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(arr)[0]
                conf = float(max(proba))
            else:
                conf = 1.0
            return pred, conf
        
        # Get actual labels if available
        actual_labels = y_sim.iloc[indices].tolist() if y_sim is not None else []
        
        results = []
        for i, (_, sample_row) in enumerate(samples.iterrows()):
            row_array = sample_row.to_numpy(dtype=float)
            if model_name == 'auto':
                candidate_preds = []
                for m in available_models:
                    pred, conf = predict_with_model(m, row_array)
                    candidate_preds.append({'model': m, 'prediction': int(pred), 'confidence': conf})

                # Confidence-thresholded voting
                high_conf = [r for r in candidate_preds if r['confidence'] >= ENSEMBLE_CONF_THRESHOLD]
                vote_pool = high_conf if high_conf else candidate_preds

                preds = [r['prediction'] for r in vote_pool]
                counts = Counter(preds)
                top_pred = counts.most_common(1)[0][0]

                top_models = [r for r in vote_pool if r['prediction'] == top_pred]
                best = max(top_models, key=lambda r: r['confidence'])

                pred = top_pred
                conf = best['confidence']
                selected_model = 'ensemble'
            else:
                pred, conf = predict_with_model(model_name, row_array)
                selected_model = model_name

            result = {
                'packet_id': int(indices[i]),
                'prediction': int(pred),
                'label': 'BENIGN' if pred == 0 else 'ATTACK',
                'confidence': conf,
                'timestamp': datetime.now().isoformat(),
                'model': selected_model
            }
            if actual_labels:
                result['actual'] = int(actual_labels[i])
                result['actual_label'] = 'BENIGN' if actual_labels[i] == 0 else 'ATTACK'
                result['correct'] = int(pred) == int(actual_labels[i])
            
            results.append(result)
            
            # Update stats
            stats['total_packets'] += 1
            if pred == 0:
                stats['benign_count'] += 1
            else:
                stats['attack_count'] += 1
        
        return jsonify({
            'results': results,
            'model': model_name,
            'stats': stats
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify(stats)

@app.route('/api/reset_stats', methods=['POST'])
def reset_stats():
    """Reset statistics"""
    stats['total_packets'] = 0
    stats['benign_count'] = 0
    stats['attack_count'] = 0
    stats['last_prediction'] = None
    return jsonify({'message': 'Statistics reset successfully'})

@app.route('/api/model_info/<model_name>')
def model_info(model_name):
    """Get information about a specific model"""
    if model_name not in models:
        return jsonify({'error': 'Model not found'}), 404
    
    if models[model_name] is None:
        return jsonify({'error': 'Model not trained yet', 'available': False}), 404
    
    model = models[model_name]
    
    info = {
        'name': model_name,
        'available': True,
        'type': type(model).__name__,
        'has_scaler': scalers.get(model_name) is not None,
        'feature_count': len(feature_names),
        'supports_proba': bool(getattr(model, 'predict_proba', None))
    }
    
    # Add model-specific info
    if hasattr(model, 'n_estimators'):
        info['n_estimators'] = model.n_estimators
    if hasattr(model, 'max_depth'):
        info['max_depth'] = model.max_depth
    if hasattr(model, 'feature_importances_'):
        # Get top 10 features
        importances = model.feature_importances_
        if feature_names:
            feat_imp = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:10]
            info['top_features'] = [{'name': name, 'importance': float(imp)} for name, imp in feat_imp]
    
    return jsonify(info)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("SmartIDS Web Interface Starting...")
    print("="*60)
    print(f"Models loaded: {sum(1 for m in models.values() if m is not None)}/{len(models)}")
    print(f"Simulation data: {len(X_sim) if X_sim is not None else 0} packets")
    print(f"Features: {len(feature_names)}")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5001)

