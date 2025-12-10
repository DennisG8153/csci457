import os
import psutil

import numpy as np
# TODO: Remove, not using these libraries because we are not training here
#from sklearn.model_selection import train_test_split 
#from tensorflow.keras import models, layers  # type: ignore
import FeatureExtractor # Can use reload_unique_features, unique_features dictionary, and constants like FEATURE_TYPES

# NOTE: FEATURE_TYPES does not need to be created because it exists in FeatureExtractor.FEATURE_TYPES
'''FEATURE_TYPES: list[str] = [
    "permissions", 
    "used_hsware", 
    "intents", 
    "api_calls", 
    "libraries", 
    "urls"
]'''

ROOT_DIRECTORY = r"..\reduced_extracted_features"
#ROOT_DIRECTORY = (r".\exampleFeatures") # TODO: Maybe make test mode?
IN_DIRECTORY_BENIGN = os.path.join(ROOT_DIRECTORY, r'benign_features')
IN_DIRECTORY_MALICIOUS = os.path.join(ROOT_DIRECTORY, r'malicious_features')
IN_DIRECTORY_UNIQUE = os.path.join(ROOT_DIRECTORY, r'unique_features')
#IN_DIRECTORY_UNIQUE = os.path.join(ROOT_DIRECTORY, r'unique_features')

OUT_DIRECTORY = r".\vectors"
VECTORS_FILENAME = r"vectors.npy"
LABELS_FILENAME = r"labels.npy"
NAMES_FILENAME = r"names.npy"

# Directory to print vectors to. To test if they are printing consistently
TEST_DIRECTORY = r"..\test_vectors"
TEST_VECTORS_FILENAME = r"vectors.txt"
TEST_LABELS_FILENAME = r"labels.txt"
TEST_NAMES_FILENAME = r"names.txt"

# Control Switchs:
# Tests Loading Vectors from file instead of building and saving
TEST_LOAD = False
# Prints Vectors to file so they can be compared
PRINT = True

# NOTE: Shouldn't use reload_unique_features() from FeatureExtractor because it is easier if the dictionary combines every feature type into one
def load_unique_feature_index(unique_dir: str) -> dict[str, int]:    
    unique_feature_index: dict[str : int] = {}
    index = 0 # NOTE: switched list to a counter instead to avoid traversing the dictionary twice

    for feature_type in FeatureExtractor.FEATURE_TYPES: # for each file
        filename = f"unique_{feature_type}.txt"
        fpath = os.path.join(unique_dir, filename)

        if not os.path.isfile(fpath): # Check if the file is there
            print(f"[WARN] Unique feature file missing, skipping: {fpath}")
            continue

        with open(fpath, "r") as file: # open the file
            for line in file:
                feature = line.strip()
                if feature and feature not in unique_feature_index: # add the feature to the dictionary if it is not already in there and it is not empty
                    unique_feature_index[feature] = index # Store the index as the value
                    index += 1 # Increment the index

    print(f"[INFO] Loaded {len(unique_feature_index)} unique features from: {unique_dir}")
    return unique_feature_index 
    #return feat_list, feat_index # TODO: feat_list isn't needed, remove

# Build dataset from malicious/benign feature dirs
def build_vector_dataset(malicious_dir: str, benign_dir: str, feature_index: dict[str, int]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    '''
    NOTE: NAME CHANGE: was load_vector_dataset, load_vector_dataset now loads from existing file
    '''

    assert feature_index is not None, "feature_index must be provided"

    #process = psutil.Process(os.getpid())
    
    input_size = len(feature_index)
    vectors: list[np.ndarray] = []
    labels: list[int] = []
    names: list[str] = []

    count = 0

    for label, feature_dir in [(1, malicious_dir), (0, benign_dir)]:
        if not os.path.isdir(feature_dir):
            print(f"[WARN] Feature directory not found, skipping: {feature_dir}")
            continue

        for filename in os.listdir(feature_dir):
            if not filename.endswith(".txt"):
                continue

            file_path = os.path.join(feature_dir, filename)
            #print(f"Memory Used: {process.memory_info().rss / 1024 ** 2:.2f} MB")
            print(count)
            count += 1
            vector = feature_file_to_vector(file_path, feature_index, input_size)
            vectors.append(vector)
            labels.append(label)
            names.append(filename)

    vector_arr = np.array(vectors, dtype=np.bool)
    label_arr = np.array(labels, dtype=np.bool)

    print(f"[INFO] Loaded Vector dataset: {vector_arr.shape[0]} samples, {vector_arr.shape[1]} features")
    return vector_arr, label_arr, names

def feature_file_to_vector(feature_file_path: str, feature_index: dict[str, int], dimension: int) -> np.ndarray:
    
    vector = np.zeros(dimension, dtype=np.int8)

    try:
        with open(feature_file_path, "r") as file:
            for line in file:
                feature = line.strip()
                if feature in feature_index:
                    vector[feature_index[feature]] = 1#.0
        file.close()
    except Exception as e:
        print(f"[ERROR] Failed to read features from {feature_file_path}: {e}")

    return vector

# save computed vectors for future use
def save_vector_dataset(out_dir: str, vectors: np.ndarray, labels: np.ndarray, names: list[str]):
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    np.save(os.path.join(out_dir, VECTORS_FILENAME), vectors)
    np.save(os.path.join(out_dir, LABELS_FILENAME), labels)
    np.save(os.path.join(out_dir, NAMES_FILENAME), np.array(names))

def load_vector_dataset(in_dir: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
    '''
    NOTE: NAME CHANGE: THIS READS FROM AN EXISTING .npy FILE, DOES NOT BUILD DATASET
    '''
    vectors = any #np.ndarray() # TODO: maybe throw an exception, don't like returning empty objects
    labels = any #np.ndarray()
    names = list[str]

    if os.path.exists(in_dir):
        vectors = np.load(os.path.join(in_dir, VECTORS_FILENAME))
        labels = np.load(os.path.join(in_dir, LABELS_FILENAME))
        names = np.load(os.path.join(in_dir, NAMES_FILENAME)).tolist()
    else:
        print(f"[ERROR] {in_dir} directory does not exist")

    return vectors, labels, names

# Simple print function
def print_dict(dictionary = dict[any, any]):
    for key in dictionary:
        print(f"{key} : {dictionary[key]}")

def print_vectors_to_file(out_dir: str, vectors: np.ndarray, labels: np.ndarray, names: list[str]):
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    vectors_file_path = os.path.join(out_dir, TEST_VECTORS_FILENAME)
    labels_file_path = os.path.join(out_dir, TEST_LABELS_FILENAME)
    names_file_path = os.path.join(out_dir, TEST_NAMES_FILENAME)

    try:
        with open(vectors_file_path, 'w') as file:
            for vector in vectors:
                for element in vector:
                    file.write(f"{element} ")
                file.write("\n")
    except Exception as e:
        print(f"Error writing to {TEST_VECTORS_FILENAME} : {e}")

    try:
        with open(labels_file_path, 'w') as file:
            for label in labels:
                file.write(f"{label}\n")
    except Exception as e:
        print(f"Error writing to {TEST_LABELS_FILENAME} : {e}")

    try:
        with open(names_file_path, 'w') as file:
            for name in names:
                file.write(f"{name}\n")
    except Exception as e:
        print(f"Error writing to {TEST_NAMES_FILENAME} : {e}")

# Main script 
if __name__ == "__main__":

    if not TEST_LOAD:
        # 1) Build global feature index from ALL six unique_*.txt files
        feature_index = load_unique_feature_index(IN_DIRECTORY_UNIQUE)
        if not feature_index:
            raise SystemExit( # TODO: Not a fan of this type of exit, but maybe this is the better way to do it
                "[FATAL] No features loaded. Check that your unique_*.txt files exist "
                f"in {IN_DIRECTORY_UNIQUE}"
            )

        # Test to see if index is preserved
        #print_dict(feature_index)
        
        # 2) Build feature vectors for example APKs
        vectors, labels, names = build_vector_dataset(IN_DIRECTORY_MALICIOUS, IN_DIRECTORY_BENIGN, feature_index)

        # 3) Check that features were actually loaded
        if vectors.size == 0:
            raise SystemExit(
                "[FATAL] No samples were loaded. Check that exampleFeatures/"
                "malicious_features and exampleFeatures/benign_features contain .txt files."
            )
        
        save_vector_dataset(OUT_DIRECTORY, vectors, labels, names)
    else:
        vectors, labels, names = load_vector_dataset(OUT_DIRECTORY)

    # Vector tests
    if PRINT:
        print_vectors_to_file(TEST_DIRECTORY, vectors, labels, names)

    '''
    for vector, label, name in zip(vectors, labels, names):
        print(f"{vector}")
        print(f"{label}")
        print(f"{name}")
    #'''
    #print(f"{vectors[len(vectors) - 1]}")
    #print(f"{labels[len(labels) - 1]}")
    #for label in labels:
    #   print(label)
    #print(len(vectors))
    #print(len(labels))
    #print(len(names))



    # Depricated TODO: Remove
    '''
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
    '''

    # TODO: Not training here, remove later
'''
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
'''