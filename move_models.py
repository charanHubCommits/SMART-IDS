#!/usr/bin/env python3
"""
Move models from Jupyter notebook to Flask app location
"""
import shutil
import os

print("Moving models from Jupyter notebook to Flask app...")

# Create project_files/models directory
os.makedirs('project_files/models', exist_ok=True)

# Move models if they exist
models_to_move = [
    ('models/random_forest.pkl', 'project_files/models/random_forest.pkl'),
    ('models/scaler.pkl', 'project_files/models/scaler.pkl'),
    ('models/feature_names.pkl', 'project_files/models/feature_names.pkl')
]

for source, destination in models_to_move:
    if os.path.exists(source):
        shutil.copy2(source, destination)
        print(f"Moved {source} -> {destination}")
    else:
        print(f"Not found: {source}")

print("\nModels ready for Flask web app!")
print("Location: project_files/models/")
print("Run: python app.py")




