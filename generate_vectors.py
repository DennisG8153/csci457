import os
import numpy as np
from collections import defaultdict

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

def create_feature_vectors(benign_dir, malicious_dir, feature_list, feature_to_index):
    """Create feature vectors for all files"""
    X_vectors = []
    y_labels = []
    
    # Process benign files (label = 0)
    benign_files = sorted([f for f in os.listdir(benign_dir) if f.endswith('.txt')])
    print(f"Processing {len(benign_files)} benign files...")
    
    for filename in benign_files:
        filepath = os.path.join(benign_dir, filename)
        features = parse_feature_file(filepath)
        
        # Create feature vector
        vector = np.zeros(len(feature_list))
        for feature_name, count in features.items():
            if feature_name in feature_to_index:
                vector[feature_to_index[feature_name]] = count
        
        X_vectors.append(vector)
        y_labels.append(0)  # Benign = 0
    
    # Process malicious files (label = 1)
    malicious_files = sorted([f for f in os.listdir(malicious_dir) if f.endswith('.txt')])
    print(f"Processing {len(malicious_files)} malicious files...")
    
    for filename in malicious_files:
        filepath = os.path.join(malicious_dir, filename)
        features = parse_feature_file(filepath)
        
        # Create feature vector
        vector = np.zeros(len(feature_list),dtype=np.float32)
        for feature_name, count in features.items():
            if feature_name in feature_to_index:
                vector[feature_to_index[feature_name]] = count
        
        X_vectors.append(vector)
        y_labels.append(1)  # Malicious = 1
    
      # Convert lists to numpy arrays with optimized dtype
    X_vectors = np.array(X_vectors, dtype=np.float32)
    y_labels = np.array(y_labels, dtype=np.int8)

    return X_vectors, y_labels

def main():
    print("Loading unique features...")
    feature_list, feature_to_index = load_unique_features()
    print(f"Found {len(feature_list)} unique features")
    
    print("\nCreating feature vectors...")
    X_vectors, y_labels = create_feature_vectors(
        'benign_features',
        'malicious_features',
        feature_list,
        feature_to_index
    )
    
    print(f"\nX_vectors shape: {X_vectors.shape}")
    print(f"y_labels shape: {y_labels.shape}")
    print(f"Feature list length: {len(feature_list)}")
    
    # Save numpy arrays
    print("\nSaving numpy arrays...")
    np.save('X_vectors.npy', X_vectors)
    np.save('y_labels.npy', y_labels)
    np.save('feature_list.npy', np.array(feature_list, dtype=object))
    
    print("\nDone! Files saved:")
    print("  - X_vectors.npy")
    print("  - y_labels.npy")
    print("  - feature_list.npy")
    
    # Print some statistics
    print(f"\nStatistics:")
    print(f"  - Total samples: {len(y_labels)}")
    print(f"  - Benign samples: {np.sum(y_labels == 0)}")
    print(f"  - Malicious samples: {np.sum(y_labels == 1)}")
    print(f"  - Feature vector dimension: {X_vectors.shape[1]}")

if __name__ == '__main__':
    main()

