import os
import csv
import numpy as np
import psutil


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

OUT_DIRECTORY = r"..\vectors"
VECTORS_FILENAME = r"vectors.npy"
LABELS_FILENAME = r"labels.npy"
NAMES_FILENAME = r"names.npy"

# Directory to print vectors to, to test if they are printing consistently
READABLE_DIRECTORY = r"..\readable_vectors"

# Control Switchs:
LOAD = False # Loads Vectors from file instead of building and saving
PRINT = True # Prints Vectors to file so they can be compared

# NOTE: Shouldn't use reload_unique_features() from FeatureExtractor because it is easier if the dictionary combines every feature type into one
def load_unique_feature_index(unique_dir: str) -> dict[str, int]:    
    unique_feature_index: dict[str : int] = {}
    index = 0 # NOTE: switched list to a counter instead to avoid traversing the dictionary twice

    for feature_type, feature_tag in zip(FeatureExtractor.FEATURE_TYPES, FeatureExtractor.FEATURE_TAGS):
        filename = f"unique_{feature_type}.txt"
        file_path = os.path.join(unique_dir, filename)

        if not os.path.isfile(file_path):
            print(f"[WARN] Unique feature file not found, skipping: {file_path}")
            continue
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                tag, _, body = line.partition(": ")
                if tag != feature_tag:
                    continue
                parts = body.split()
                if not parts:
                    continue
                feat_name = parts[0].strip()
                if feat_name and feat_naame not in unique_feature_index:
                    unique_feature_index[feat_name] = index
                    index += 1

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

    vectors_file_path = os.path.join(out_dir, VECTORS_FILENAME)
    labels_file_path = os.path.join(out_dir, LABELS_FILENAME)
    names_file_path = os.path.join(out_dir, NAMES_FILENAME)

    try:
        with open(vectors_file_path, 'w') as file:
            for vector in vectors:
                for element in vector:
                    file.write(f"{element} ")
                file.write("\n")
    except Exception as e:
        print(f"Error writing to {VECTORS_FILENAME} : {e}")

    try:
        with open(labels_file_path, 'w') as file:
            for label in labels:
                file.write(f"{label}\n")
    except Exception as e:
        print(f"Error writing to {LABELS_FILENAME} : {e}")

    try:
        with open(names_file_path, 'w') as file:
            for name in names:
                file.write(f"{name}\n")
    except Exception as e:
        print(f"Error writing to {NAMES_FILENAME} : {e}")



def write_vectors_to_csv(vectors: np.ndarray, csv_path: str) -> None:

    if not isinstance(vectors, np.ndarray):
        vectors = np.array(vectors)

    n_samples, n_features = vectors.shape
    print(f"Writing {n_samples} vectors × {n_features} features to {csv_path}")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        for i in range(n_samples):
            writer.writerow(vectors[i])

# Main script 
if __name__ == "__main__":

    if not LOAD:
        # Build global feature index from ALL six unique_*.txt files
        feature_index = load_unique_feature_index(IN_DIRECTORY_UNIQUE)
        if not feature_index:
            raise SystemExit( # TODO: Not a fan of this type of exit, but maybe this is the better way to do it
                "[FATAL] No features loaded. Check that your unique_*.txt files exist "
                f"in {IN_DIRECTORY_UNIQUE}"
            )

        # Test to see if index is preserved
        #print_dict(feature_index)
        
        # Build feature vectors for example APKs
        vectors, labels, names = build_vector_dataset(IN_DIRECTORY_MALICIOUS, IN_DIRECTORY_BENIGN, feature_index)

        # Check that features were actually loaded
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
        print_vectors_to_file(READABLE_DIRECTORY, vectors, labels, names)