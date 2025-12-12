import os
import sys
import numpy as np
from collections import defaultdict
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import tensorflow as tf
from tensorflow import keras

# Try to import tqdm for progress bar, fallback to simple iteration if not available
try:
    from tqdm import tqdm
    USE_TQDM = True
except ImportError:
    USE_TQDM = False
    def tqdm(iterable, desc=""):
        return iterable

# Import functions from predict.py
from predict import load_feature_list, vectorize_apk, load_model, parse_feature_file

def batch_predict(feature_files, true_labels, feature_list, feature_to_index, model):
    """Batch predict on multiple feature files"""
    predictions = []
    scores = []
    
    print(f"Processing {len(feature_files)} files...")
    
    iterator = tqdm(feature_files, desc="Predicting") if USE_TQDM else feature_files
    for i, filepath in enumerate(iterator):
        if not USE_TQDM and (i + 1) % 50 == 0:
            print(f"  Processed {i + 1}/{len(feature_files)} files...")
        try:
            # Vectorize APK
            vector = vectorize_apk(filepath, feature_list, feature_to_index)
            
            # Reshape for model input (same as in predict.py)
            vector = vector.astype(np.float32)
            vector = np.expand_dims(vector, axis=0)   
            vector = np.expand_dims(vector, axis=-1)
            
            # Predict
            prediction = model.predict(vector, verbose=0)
            
            # Get label and score
            score = float(prediction[0][0])
            label = 1 if score >= 0.5 else 0
            
            predictions.append(label)
            scores.append(score)
        except Exception as e:
            print(f"\nError processing {filepath}: {e}")
            # Use default prediction (benign) if error occurs
            predictions.append(0)
            scores.append(0.0)
    
    return np.array(predictions), np.array(scores)

def evaluate_model(benign_dir='benign_features', malicious_dir='malicious_features', 
                   model_path='apk_malware_cnn_model.keras'):
    """Evaluate model on test dataset"""
    
    print("="*60)
    print("Model Evaluation")
    print("="*60)
    
    # Load feature list
    print("\n[1/4] Loading feature list...")
    feature_list, feature_to_index = load_feature_list()
    print(f"Loaded {len(feature_list)} features")
    
    # Load model
    print("\n[2/4] Loading model...")
    model = load_model(model_path)
    
    # Collect all feature files and their true labels
    print("\n[3/4] Collecting test files...")
    feature_files = []
    true_labels = []
    
    # Process benign files (label = 0)
    benign_files = sorted([f for f in os.listdir(benign_dir) if f.endswith('.txt')])
    for filename in benign_files:
        filepath = os.path.join(benign_dir, filename)
        feature_files.append(filepath)
        true_labels.append(0)
    
    # Process malicious files (label = 1)
    malicious_files = sorted([f for f in os.listdir(malicious_dir) if f.endswith('.txt')])
    for filename in malicious_files:
        filepath = os.path.join(malicious_dir, filename)
        feature_files.append(filepath)
        true_labels.append(1)
    
    true_labels = np.array(true_labels)
    
    print(f"Total test files: {len(feature_files)}")
    print(f"  - Benign: {np.sum(true_labels == 0)}")
    print(f"  - Malicious: {np.sum(true_labels == 1)}")
    
    # Batch predict
    print("\n[4/4] Running predictions...")
    predicted_labels, predicted_scores = batch_predict(
        feature_files, true_labels, feature_list, feature_to_index, model
    )
    
    # Calculate metrics
    print("\n" + "="*60)
    print("Evaluation Results")
    print("="*60)
    
    accuracy = accuracy_score(true_labels, predicted_labels)
    precision = precision_score(true_labels, predicted_labels, zero_division=0)
    recall = recall_score(true_labels, predicted_labels, zero_division=0)
    f1 = f1_score(true_labels, predicted_labels, zero_division=0)
    
    print(f"\nOverall Metrics:")
    print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"  Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"  F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    
    # Confusion Matrix
    cm = confusion_matrix(true_labels, predicted_labels)
    print(f"\nConfusion Matrix:")
    print(f"                Predicted")
    print(f"              Benign  Malicious")
    print(f"Actual Benign    {cm[0][0]:4d}      {cm[0][1]:4d}")
    print(f"      Malicious  {cm[1][0]:4d}      {cm[1][1]:4d}")
    
    # Calculate per-class metrics
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\nDetailed Metrics:")
    print(f"  True Positives (TP):  {tp:4d} - Correctly identified malicious")
    print(f"  True Negatives (TN):  {tn:4d} - Correctly identified benign")
    print(f"  False Positives (FP): {fp:4d} - Benign misclassified as malicious")
    print(f"  False Negatives (FN): {fn:4d} - Malicious misclassified as benign")
    
    # Per-class accuracy
    benign_accuracy = tn / (tn + fp) if (tn + fp) > 0 else 0
    malicious_accuracy = tp / (tp + fn) if (tp + fn) > 0 else 0
    
    print(f"\nPer-Class Accuracy:")
    print(f"  Benign accuracy:    {benign_accuracy:.4f} ({benign_accuracy*100:.2f}%)")
    print(f"  Malicious accuracy: {malicious_accuracy:.4f} ({malicious_accuracy*100:.2f}%)")
    
    # Classification report
    print(f"\nClassification Report:")
    print(classification_report(true_labels, predicted_labels, 
                              target_names=['Benign', 'Malicious'], 
                              digits=4))
    
    # Score statistics
    benign_scores = predicted_scores[true_labels == 0]
    malicious_scores = predicted_scores[true_labels == 1]
    
    print(f"\nScore Statistics:")
    print(f"  Benign samples:")
    print(f"    Mean score: {np.mean(benign_scores):.4f}")
    print(f"    Std score:  {np.std(benign_scores):.4f}")
    print(f"    Min score:  {np.min(benign_scores):.4f}")
    print(f"    Max score:  {np.max(benign_scores):.4f}")
    print(f"  Malicious samples:")
    print(f"    Mean score: {np.mean(malicious_scores):.4f}")
    print(f"    Std score:  {np.std(malicious_scores):.4f}")
    print(f"    Min score:  {np.min(malicious_scores):.4f}")
    print(f"    Max score:  {np.max(malicious_scores):.4f}")
    
    print("\n" + "="*60)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm,
        'true_labels': true_labels,
        'predicted_labels': predicted_labels,
        'predicted_scores': predicted_scores
    }

def main():
    if len(sys.argv) > 1:
        model_path = sys.argv[1]
    else:
        model_path = 'apk_malware_cnn_model.keras'
    
    if len(sys.argv) > 2:
        benign_dir = sys.argv[2]
    else:
        benign_dir = 'benign_features'
    
    if len(sys.argv) > 3:
        malicious_dir = sys.argv[3]
    else:
        malicious_dir = 'malicious_features'
    
    try:
        results = evaluate_model(benign_dir, malicious_dir, model_path)
    except Exception as e:
        print(f"\nError during evaluation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

