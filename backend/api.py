"""
Sentinel IDS - Flask Backend API
---------------------------------
Install dependencies:
    pip install flask flask-cors tensorflow joblib pandas numpy scikit-learn h5py

Run:
    python api.py

The server starts on http://localhost:5000
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
import os
import traceback

# Suppress noisy TensorFlow logs
os.environ['TF_CPP_MIN_LOG_LEVEL']  = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

import tensorflow as tf
from tensorflow.keras import Input
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout
from tensorflow.keras.models import Model
import h5py
import joblib

app = Flask(__name__)
CORS(app)

# ── PATHS ─────────────────────────────────────────────────────────────────────
# Your exact file paths — update the filename if yours differs
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

WEIGHTS_PATH = os.path.join(MODELS_DIR, "IDS_model_weights.weights.h5")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.save")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.save")


# ── EXPECTED FEATURE COLUMNS (78 features, CICIDS 2017, no Label) ─────────────
EXPECTED_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]


# ═════════════════════════════════════════════════════════════════════════════
#  BUILD CNN ARCHITECTURE
#  Your file is a weights-only .h5 — we rebuild the architecture
#  then load the weights into it manually using h5py.
#
#  Architecture confirmed from your weights file:
#    conv1d        filters=64,  kernel=3, input=(78,1)
#    max_pooling1d pool=2
#    conv1d_1      filters=128, kernel=3
#    max_pooling1d pool=2
#    flatten       → 2304
#    dense         128, relu
#    dense_1       128, relu
#    dropout       0.3
#    dense_2       15,  softmax
# ═════════════════════════════════════════════════════════════════════════════
def build_model(num_classes=15):
    inputs = Input(shape=(78, 1), name='input')
    x = Conv1D(64,  3, activation='relu', name='conv1d'  )(inputs)
    x = MaxPooling1D(2, name='max_pooling1d'  )(x)
    x = Conv1D(128, 3, activation='relu', name='conv1d_1')(x)
    x = MaxPooling1D(2, name='max_pooling1d_1')(x)
    x = Flatten(name='flatten')(x)
    x = Dense(128, activation='relu', name='dense'  )(x)
    x = Dense(128, activation='relu', name='dense_1')(x)
    x = Dropout(0.3, name='dropout')(x)
    x = Dense(num_classes, activation='softmax', name='dense_2')(x)
    mdl = Model(inputs=inputs, outputs=x)
    mdl.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    return mdl


def load_weights_manually(mdl, weights_path):
    """Load weights from a weights-only .h5 file using h5py directly."""
    with h5py.File(weights_path, 'r') as f:
        layers_group = f['layers']
        loaded_count = 0
        for layer in mdl.layers:
            if layer.name in layers_group:
                vars_group = layers_group[layer.name]['vars']
                weights = [vars_group[str(i)][()] for i in range(len(vars_group))]
                if weights:
                    layer.set_weights(weights)
                    loaded_count += 1
    return loaded_count


# ═════════════════════════════════════════════════════════════════════════════
#  STARTUP — check files, build model, load weights
# ═════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 55)
print("  Sentinel IDS Backend API — Starting Up")
print("=" * 55)
print(f"\n  Models folder : {MODELS_DIR}\n")

# Check all 3 files exist
all_files_found = True
for label, path in [
    ("IDS_model_weights.weights.h5", WEIGHTS_PATH),
    ("scaler.save",                  SCALER_PATH),
    ("label_encoder.save",           LABEL_ENCODER_PATH),
]:
    if os.path.exists(path):
        kb = os.path.getsize(path) // 1024
        print(f"  ✓  {label}  ({kb} KB)")
    else:
        print(f"  ✗  {label}  — NOT FOUND")
        print(f"     Expected at: {path}")
        all_files_found = False

print()

# Load label encoder
label_encoder = None
try:
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    print(f"✓ Label encoder loaded — {len(label_encoder.classes_)} classes")
    print(f"  {list(label_encoder.classes_)}")
except Exception as e:
    print(f"✗ Label encoder failed: {e}")

# Load scaler
scaler = None
try:
    scaler = joblib.load(SCALER_PATH)
    print(f"✓ Scaler loaded — {scaler.n_features_in_} features")
except Exception as e:
    print(f"✗ Scaler failed: {e}")

# Build architecture and load weights
model = None
try:
    num_classes = len(label_encoder.classes_) if label_encoder else 15
    print(f"\nBuilding CNN architecture ({num_classes} output classes)...")
    model = build_model(num_classes)
    print("✓ Architecture built")

    print("Loading weights from .h5 file...")
    n = load_weights_manually(model, WEIGHTS_PATH)
    print(f"✓ Weights loaded — {n} layers restored")

    # Sanity check
    dummy_input = np.zeros((1, 78, 1), dtype=np.float32)
    test_pred   = model.predict(dummy_input, verbose=0)
    assert abs(float(test_pred.sum()) - 1.0) < 0.01, "Output does not sum to 1"
    print("✓ Sanity check passed — model outputs valid probabilities")

except Exception as e:
    print(f"✗ Model loading failed: {e}")
    traceback.print_exc()
    model = None

# Final status
print()
if model and scaler and label_encoder:
    print("=" * 55)
    print("  ✅ ALL COMPONENTS LOADED — API IS READY")
    print("  Running on http://localhost:5000")
    print("=" * 55 + "\n")
else:
    missing = []
    if not model:         missing.append("model weights")
    if not scaler:        missing.append("scaler")
    if not label_encoder: missing.append("label encoder")
    print("=" * 55)
    print(f"  ⚠️  NOT READY — failed to load: {', '.join(missing)}")
    print(f"  Check that all 3 files are in: {MODELS_DIR}")
    print("=" * 55 + "\n")


# ═════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/health', methods=['GET'])
def health():
    """Health check — used by the frontend to show API status."""
    return jsonify({
        'status':         'ok',
        'all_ready':      all([model, scaler, label_encoder]),
        'model_loaded':   model         is not None,
        'scaler_loaded':  scaler        is not None,
        'encoder_loaded': label_encoder is not None,
        'classes':        list(label_encoder.classes_) if label_encoder else [],
        'models_dir':     MODELS_DIR,
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Accepts a CSV file, runs the CNN model, returns predictions.
    Request : multipart/form-data → field 'file' (.csv)
    Response: JSON with per-row predictions and summary
    """

    # Guard — all components must be ready
    if not all([model, scaler, label_encoder]):
        missing = []
        if not model:         missing.append("IDS_model_weights.weights.h5")
        if not scaler:        missing.append("scaler.save")
        if not label_encoder: missing.append("label_encoder.save")
        return jsonify({
            'error':   'Model not ready. Some components failed to load.',
            'missing': missing,
            'fix':     f'Make sure all 3 files are in: {MODELS_DIR}'
        }), 500

    if 'file' not in request.files:
        return jsonify({'error': 'No file sent. Upload a CSV as form-data field "file".'}), 400

    file = request.files['file']
    if not file.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Only .csv files are accepted.'}), 400

    try:
        # Read CSV
        df = pd.read_csv(file)
        print(f"\n📄 Received: {file.filename}  shape={df.shape}")

        # Clean column names
        df.columns = df.columns.str.strip()

        # Drop Label if present
        if 'Label' in df.columns:
            df = df.drop(columns=['Label'])

        # Validate columns
        missing_cols = [c for c in EXPECTED_COLUMNS if c not in df.columns]
        if missing_cols:
            return jsonify({
                'error':           f'CSV is missing {len(missing_cols)} required column(s).',
                'missing_columns': missing_cols[:10],
                'hint':            'Upload a CICIDS 2017 format CSV (78 feature columns, no Label).',
                'your_columns':    list(df.columns[:10]),
            }), 400

        # Keep only expected columns in correct order
        df = df[EXPECTED_COLUMNS]

        # Remove inf and NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        if len(df) == 0:
            return jsonify({'error': 'No valid rows after cleaning. Check for NaN or Inf values.'}), 400

        print(f"   Clean rows: {len(df)}")

        # Scale → reshape for CNN
        X        = df.values.astype(np.float32)
        X_scaled = scaler.transform(X)
        X_cnn    = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

        # Predict
        print("   Running CNN predictions...")
        preds       = model.predict(X_cnn, verbose=0, batch_size=512)
        pred_idx    = np.argmax(preds, axis=1)
        pred_labels = label_encoder.inverse_transform(pred_idx)
        confidence  = np.max(preds, axis=1)

        # Summary
        series       = pd.Series(pred_labels)
        distribution = series.value_counts().to_dict()
        threat_count = int((series != 'BENIGN').sum())
        benign_count = int((series == 'BENIGN').sum())

        print(f"   ✓ Done — threats: {threat_count}  benign: {benign_count}")

        # Per-row results (max 500)
        n = min(len(pred_labels), 500)
        results = [
            {
                'row':        i + 1,
                'prediction': pred_labels[i],
                'confidence': round(float(confidence[i]) * 100, 2),
                'is_threat':  bool(pred_labels[i] != 'BENIGN'),
            }
            for i in range(n)
        ]

        return jsonify({
            'success':      True,
            'total_rows':   len(pred_labels),
            'threat_count': threat_count,
            'benign_count': benign_count,
            'distribution': distribution,
            'results':      results,
            'truncated':    len(pred_labels) > 500,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# ═════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
