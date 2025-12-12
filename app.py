import os
import sys
import io
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import numpy as np
from predict import load_feature_list, vectorize_apk, load_model, parse_feature_file
import tensorflow as tf
from tensorflow import keras

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global variables for model and feature list (loaded once at startup)
model = None
feature_list = None
feature_to_index = None

def init_model():
    """Initialize model and feature list (called once at startup)"""
    global model, feature_list, feature_to_index
    
    try:
        print("Initializing model and feature list...")
        feature_list, feature_to_index = load_feature_list()
        print(f"Loaded {len(feature_list)} features")
        
        model = load_model('apk_malware_cnn_model.keras')
        print("Model loaded successfully!")
    except Exception as e:
        print(f"ERROR: Failed to initialize model: {e}")
        print("\nPlease ensure:")
        print("  1. apk_malware_cnn_model.keras exists in the current directory")
        print("  2. feature_list.npy exists OR unique_features/ directory exists")
        print("  3. All required dependencies are installed")
        raise

def predict_from_content(content):
    """Predict from file content string"""
    global model, feature_list, feature_to_index
    
    # Parse features from content
    features = {}
    for line in content.split('\n'):
        line = line.strip()
        if line:
            parts = line.rsplit(' ', 1)
            if len(parts) == 2:
                feature_name = parts[0]
                try:
                    count = int(parts[1])
                    features[feature_name] = count
                except ValueError:
                    continue
    
    # Create feature vector
    vector = np.zeros(len(feature_list), dtype=np.float32)
    for feature_name, count in features.items():
        if feature_name in feature_to_index:
            vector[feature_to_index[feature_name]] = count
    
    # Reshape for model input
    vector = vector.astype(np.float32)
    vector = np.expand_dims(vector, axis=0)   
    vector = np.expand_dims(vector, axis=-1)
    
    # Predict
    prediction = model.predict(vector, verbose=0)
    
    # Get label and score
    score = float(prediction[0][0])
    label = 1 if score >= 0.5 else 0
    
    return label, score, len(features)

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Handle prediction request"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        content = file.read().decode('utf-8')
        
        # Make prediction
        label, score, feature_count = predict_from_content(content)
        
        label_name = "Malicious" if label == 1 else "Benign"
        confidence = score if label == 1 else (1 - score)
        
        result = {
            'success': True,
            'label': label,
            'label_name': label_name,
            'score': score,
            'confidence': confidence,
            'feature_count': feature_count,
            'message': f'The APK is classified as {label_name} with {confidence*100:.2f}% confidence.'
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'features_loaded': feature_list is not None
    })

if __name__ == '__main__':
    print("="*60)
    print("APK Malware Detector Web Demo")
    print("="*60)
    
    try:
        init_model()
        print("\n" + "="*60)
        print("Server is ready!")
        print("="*60)
        print("\nAccess the web interface at:")
        print("  Local:   http://127.0.0.1:5000")
        print("  Network: http://0.0.0.0:5000")
        print("\nPress Ctrl+C to stop the server")
        print("="*60 + "\n")
        
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"\n\nFATAL ERROR: {e}")
        print("\nServer failed to start. Please check the error messages above.")
        import traceback
        traceback.print_exc()
        sys.exit(1)

