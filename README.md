# SmartIDS - Smart Intrusion Detection System

A real-time network intrusion detection system using machine learning models to classify network traffic as benign or malicious attacks.

## Features

- **Multi-Model Support**: Random Forest, Decision Tree, XGBoost, Logistic Regression
- **Auto Model Selection**: Automatically chooses the most confident model for each prediction
- **Live Packet Capture**: Capture real-time network traffic directly using `pyshark` and get instant predictions
- **Real-Time Simulation**: Simulate network traffic using dataset files for testing
- **Interactive Dashboard**: Web-based interface with live charts and statistics
- **Model Comparison**: Compare performance across different ML models

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone the Repository

```bash
git clone https://github.com/charanHubCommits/SMART-IDS.git
cd SMART-IDS
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

## Data Setup

The project uses the **CICIDS2017** dataset for training and simulation. The dataset files are **not included** in this repository due to their large size.

### Download CICIDS2017 Dataset

1. Visit the [CICIDS2017 dataset page](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Download the required CSV files:
   - `Monday-WorkingHours.pcap_ISCX.csv`
   - `Tuesday-WorkingHours.pcap_ISCX.csv`
   - `Wednesday-workingHours.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
   - `Friday-WorkingHours-Morning.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

3. Place all CSV files in the `data/` directory:

```bash
mkdir -p data
# Copy downloaded CSV files to data/ directory
```

Your directory structure should look like:
```
SMART-IDS/
├── data/
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   ├── Wednesday-workingHours.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│   └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
├── app.py
├── train_model.py
└── ...
```

## Model Training

**Important**: Model files (`.pkl`) are **not included** in this repository. You must train them yourself.

### Train All Models

Run the training script to generate the model files:

```bash
python train_model.py
```

This will:
- Load training data from the `data/` directory
- Train a Random Forest classifier
- Save models to `project_files/models/`
- Generate `random_forest.pkl` and `scaler.pkl`

### Train Additional Models

To train other models (Decision Tree, XGBoost, Logistic Regression, SVM), use the Jupyter notebooks in `project_files/`:

```bash
jupyter notebook project_files/
```

Then run:
- `random_forest.ipynb` - Random Forest model
- `decison_tree.ipynb` - Decision Tree model
- `xb_boost.ipynb` - XGBoost model
- `logistic_regression.ipynb` - Logistic Regression model
- `svm.ipynb` - SVM model

After training, move the models to the correct location:

```bash
python move_models.py
```

Or manually copy `.pkl` files to `project_files/models/`

## Running the Web Application

### Start the Flask Server

```bash
python app.py
```

The web interface will be available at:
- **Local**: http://127.0.0.1:5001
- **Network**: http://0.0.0.0:5001

### Using the Dashboard

1. **Select Model**: Choose a specific model or "Auto (best confidence)" mode
2. **Choose Mode**: Use the tabs on the left to select either **Simulation** or **Live Capture**
3. **Start Analysis**: 
   - *In Simulation*: Adjust the speed and click "Start Simulation"
   - *In Live Capture*: Enter your network interface (or leave blank to auto-detect) and click "Start Live Capture" (Note: may require administrator/root privileges)
4. **View Results**: See predictions, confidence scores, and statistics in real-time

## Project Structure

```
SMART-IDS/
├── app.py                      # Flask web application
├── train_model.py              # Model training script
├── move_models.py              # Utility to move models
├── requirements.txt            # Python dependencies
├── data/                       # CICIDS2017 dataset (not in repo)
│   └── *.csv                   # Dataset files (download separately)
├── project_files/
│   ├── models/                 # Trained models (generate via training)
│   │   ├── random_forest.pkl
│   │   ├── scaler.pkl
│   │   ├── feature_names.pkl
│   │   └── ...
│   └── *.ipynb                 # Jupyter notebooks for model training
├── static/
│   ├── css/
│   │   └── style.css           # Dashboard styles
│   └── js/
│       └── app.js              # Frontend JavaScript
└── templates/
    ├── index.html              # Main dashboard
    └── test.html               # Test page
```

## API Endpoints

- `GET /` - Main dashboard
- `POST /api/predict` - Single packet prediction
- `POST /api/simulate` - Simulate multiple packets
- `POST /api/live/start` - Start live packet capture thread
- `POST /api/live/stop` - Stop live packet capture thread
- `GET /api/live/results` - Get latest live packet flow features and predictions
- `GET /api/stats` - Get statistics
- `POST /api/reset_stats` - Reset statistics
- `GET /api/model_info/<model_name>` - Get model information

## Troubleshooting

### Models Not Found Error

If you see "Model not found" errors:
1. Ensure you've trained the models using `train_model.py` or the Jupyter notebooks
2. Check that `.pkl` files exist in `project_files/models/`
3. Verify the scaler file (`scaler.pkl`) is present

### Data Files Not Found

If training fails with "file not found":
1. Verify all CSV files are in the `data/` directory
2. Check file names match exactly (case-sensitive)
3. Ensure files are not corrupted

### Port Already in Use

If port 5001 is already in use:
- Change the port in `app.py` (line 421): `app.run(debug=True, host='0.0.0.0', port=5001)`

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- CICIDS2017 dataset: [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
- Flask web framework
- scikit-learn for machine learning models

