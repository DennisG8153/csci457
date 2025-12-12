import os
import sys
import numpy as np
from collections import defaultdict
import tensorflow as tf
from tensorflow import keras

def load_feature_list():
    """Load feature list and create feature_to_index mapping"""
    # Try to load from saved npy file first
    if os.path.exists('feature_list.npy'):
        print("Loading feature_list from feature_list.npy...")
        feature_list = np.load('feature_list.npy', allow_pickle=True).tolist()
        feature_to_index = {feature: idx for idx, feature in enumerate(feature_list)}
        return feature_list, feature_to_index
    else:
        # Fallback to loading from unique_features directory
        print("Loading feature_list from unique_features directory...")
        return load_unique_features()

def load_unique_features():
    """Load all unique features from the unique_features directory"""
    feature_list = []
    feature_to_index = {}
    
    # List of unique feature files
    feature_files = [
        'unique_permissions.txt',
        'unique_intents.txt',
        'unique_api_calls.txt',
        'unique_libraries.txt',
        'unique_urls.txt',
        'unique_used_hsware.txt'
    ]
    
    unique_features_dir = 'unique_features'
    
    for filename in feature_files:
        filepath = os.path.join(unique_features_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Extract feature name (remove count at the end)
                        # Format: "Feature: name count"
                        parts = line.rsplit(' ', 1)
                        if len(parts) == 2:
                            feature_name = parts[0]  # Already includes prefix like "Intent: ", "API: ", etc.
                            
                            if feature_name not in feature_to_index:
                                feature_to_index[feature_name] = len(feature_list)
                                feature_list.append(feature_name)
    
    return feature_list, feature_to_index

def parse_feature_file(filepath):
    """Parse a feature file and return a dictionary of features and their counts"""
    features = defaultdict(int)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
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
    
    return features

def vectorize_apk(apk_feature_file, feature_list, feature_to_index):
    """Convert APK feature file to feature vector"""
    features = parse_feature_file(apk_feature_file)
    
    # Create feature vector
    vector = np.zeros(len(feature_list), dtype=np.float32)
    for feature_name, count in features.items():
        if feature_name in feature_to_index:
            vector[feature_to_index[feature_name]] = count
    
    return vector

def load_model(model_path='apk_malware_cnn_model.keras'):
    """Load the trained model"""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    print(f"Loading model from {model_path}...")
    model = keras.models.load_model(model_path)
    return model

def predict(apk_feature_file, model_path='apk_malware_cnn_model.keras'):
    """Main prediction function"""
    # Load feature list
    print("Loading feature list...")
    feature_list, feature_to_index = load_feature_list()
    print(f"Loaded {len(feature_list)} features")
    
    # Load model
    model = load_model(model_path)
    
    # Vectorize APK
    print(f"Vectorizing APK features from: {apk_feature_file}")
    vector = vectorize_apk(apk_feature_file, feature_list, feature_to_index)
    
    # Reshape for model input
    vector = vector.astype(np.float32)
    vector = np.expand_dims(vector, axis=0)   
    vector = np.expand_dims(vector, axis=-1)
    
    # Predict
    print("Running prediction...")
    prediction = model.predict(vector, verbose=0)
    
    # Get label and score
    # Assuming binary classification: 0 = benign, 1 = malicious
    score = float(prediction[0][0])  # Probability of being malicious
    label = 1 if score >= 0.5 else 0
    
    # Output results
    label_name = "Malicious" if label == 1 else "Benign"
    print(f"\n{'='*50}")
    print(f"Prediction Results:")
    print(f"  Label: {label} ({label_name})")
    print(f"  Score: {score:.4f}")
    print(f"{'='*50}\n")
    
    return label, score

def main():
    if len(sys.argv) < 2:
        print("Usage: python predict.py <apk_feature_file> [model_path]")
        print("Example: python predict.py sample_apk.txt")
        print("Example: python predict.py sample_apk.txt apk_malware_cnn_model.keras")
        sys.exit(1)
    
    apk_feature_file = sys.argv[1]
    model_path = sys.argv[2] if len(sys.argv) > 2 else 'apk_malware_cnn_model.keras'
    
    if not os.path.exists(apk_feature_file):
        print(f"Error: Feature file not found: {apk_feature_file}")
        sys.exit(1)
    
    try:
        label, score = predict(apk_feature_file, model_path)
    except Exception as e:
        print(f"Error during prediction: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

