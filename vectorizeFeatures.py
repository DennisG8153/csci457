import os
from typing import Dict, List, Tuple

import numpy as np
from sklearn.model_selection import train_test_split
from tensorflow.keras import models, layers  # type: ignore

# FeatureExtractor.FEATURE_TYPES
FEATURE_TYPES: List[str] = [
    "permissions",
    "used_hsware",
    "intents",
    "api_calls",
    "libraries",
    "urls",
]

# Base where example feature files
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
EXAMPLE_BASE_DIR = os.path.join(REPO_ROOT, "exampleFeatures")

# Folders inside exampleFeatures
UNIQUE_DIR = os.path.join(EXAMPLE_BASE_DIR, "unique_features")
MALICIOUS_FEATURE_DIR = os.path.join(EXAMPLE_BASE_DIR, "malicious_features")
BENIGN_FEATURE_DIR = os.path.join(EXAMPLE_BASE_DIR, "benign_features")


def load_unique_features(unique_dir: str = UNIQUE_DIR) -> Tuple[List[str], Dict[str, int]]:
    
    feat_list: List[str] = []
    seen = set()

    for ftype in FEATURE_TYPES:
        filename = f"unique_{ftype}.txt"
        fpath = os.path.join(unique_dir, filename)

        if not os.path.isfile(fpath):
            print(f"[WARN] Unique feature file missing, skipping: {fpath}")
            continue

        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                feat = line.strip()
                if not feat or feat in seen:
                    continue
                seen.add(feat)
                feat_list.append(feat)

    feat_index: Dict[str, int] = {feat: idx for idx, feat in enumerate(feat_list)}
    print(f"[INFO] Loaded {len(feat_list)} unique features from '{unique_dir}'")
    return feat_list, feat_index


def feature_file_to_vector(
    feature_file_path: str,
    feat_index: Dict[str, int],
    dim: int,
) -> np.ndarray:
    vec = np.zeros(dim, dtype=np.float32)

    try:
        with open(feature_file_path, "r", encoding="utf-8") as f:
            for line in f:
                feat = line.strip()
                if feat in feat_index:
                    vec[feat_index[feat]] = 1.0
    except Exception as e:
        print(f"[ERROR] Failed to read features from {feature_file_path}: {e}")

    return vec


# Build dataset from malicious/benign feature dirs
def load_dataset(
    malicious_dir: str = MALICIOUS_FEATURE_DIR,
    benign_dir: str = BENIGN_FEATURE_DIR,
    feat_index: Dict[str, int] = None,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:

    assert feat_index is not None, "feat_index must be provided"

    input_size = len(feat_index)
    X: List[np.ndarray] = []
    y: List[int] = []
    names: List[str] = []

    for label, feature_dir in [(1, malicious_dir), (0, benign_dir)]:
        if not os.path.isdir(feature_dir):
            print(f"[WARN] Feature directory not found, skipping: {feature_dir}")
            continue

        for fname in os.listdir(feature_dir):
            if not fname.endswith(".txt"):
                continue

            fpath = os.path.join(feature_dir, fname)
            vec = feature_file_to_vector(fpath, feat_index, input_size)
            X.append(vec)
            y.append(label)
            names.append(fname)

    X_arr = np.array(X, dtype=np.float32)
    y_arr = np.array(y, dtype=np.int64)

    print(f"[INFO] Loaded dataset: {X_arr.shape[0]} samples, {X_arr.shape[1]} features")
    return X_arr, y_arr, names


# Optional: Simple CNN model 

def build_cnn(input_size: int) -> models.Model:
    """
    Very simple 1D CNN for binary classification over feature vectors.
    """
    model = models.Sequential(
        [
            layers.Input(shape=(input_size, 1)),
            layers.Conv1D(64, 3, activation="relu"),
            layers.MaxPooling1D(2),
            layers.Conv1D(128, 3, activation="relu"),
            layers.MaxPooling1D(2),
            layers.Flatten(),
            layers.Dense(128, activation="relu"),
            layers.Dropout(0.4),
            layers.Dense(1, activation="sigmoid"),
        ]
    )
    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


# Main script 

if __name__ == "__main__":
    # 1) Build global feature index from ALL six unique_*.txt files
    feat_list, feat_index = load_unique_features(UNIQUE_DIR)
    if not feat_list:
        raise SystemExit(
            "[FATAL] No features loaded. Check that your unique_*.txt files exist "
            f"in {UNIQUE_DIR}"
        )

    # 2) Load feature vectors for example APKs
    X, y, names = load_dataset(
        malicious_dir=MALICIOUS_FEATURE_DIR,
        benign_dir=BENIGN_FEATURE_DIR,
        feat_index=feat_index,
    )

    if X.size == 0:
        raise SystemExit(
            "[FATAL] No samples were loaded. Check that exampleFeatures/"
            "malicious_features and exampleFeatures/benign_features contain .txt files."
        )
    # --------------------------------------------------------------------------------------------------------
    # ADD: manual control for loading pre-saved vectors

    USE_SAVED_VECTORS_FOR_TRAINING = False  # set to true to load from files instead of recomputing

    if USE_SAVED_VECTORS_FOR_TRAINING:
        # load vectors previously saved
        X = np.load(os.path.join(REPO_ROOT, "X_vectors.npy"))
        y = np.load(os.path.join(REPO_ROOT, "y_labels.npy"))
        names = np.load(os.path.join(REPO_ROOT, "sample_names.npy"))
    else:
        # save computed vectors for future use
        np.save(os.path.join(REPO_ROOT, "X_vectors.npy"), X)
        np.save(os.path.join(REPO_ROOT, "y_labels.npy"), y)
        np.save(os.path.join(REPO_ROOT, "sample_names.npy"), np.array(names))

    # END ADD block
    # --------------------------------------------------------------------------------------------------------
    
    # 3) Expand dims for CNN (N, F, 1)
    X = np.expand_dims(X, -1)

    # 4) Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # 5) Build & train model
    model = build_cnn(input_size=len(feat_list))
    model.summary()

    history = model.fit(
        X_train,
        y_train,
        epochs=10,
        batch_size=32,
        validation_split=0.2,
        shuffle=True,
    )

    # 6) Evaluate
    test_loss, test_acc = model.evaluate(X_test, y_test)
    print(f"[RESULT] Test Accuracy: {test_acc:.4f}")

    # 7) Save model and feature index for later use
    model.save(os.path.join(REPO_ROOT, "apk_malware_cnn_model.keras"))
    np.save(os.path.join(REPO_ROOT, "feature_index.npy"), feat_list)
    print("[INFO] Saved model and feature index.")
