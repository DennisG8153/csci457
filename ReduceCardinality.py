"""
    ReduceCardinality.py
    Reduces the Cardinality of a Feature Set by: 
        Categorizing feature types of 
        Counting the amount of times a feature is used in the Feature Set

    Catagories:
        -
        -
        -
        
    Features are removed if: 
        They only occur once (n <= 1)
        They are used by every APK in the Data Set (n == len(Data Set))

    TODO: Needs to reduce entire Dataset and remake unique features files from that
    Catagorize API, Libraries, URLs
    Add a count to each feature, only groups should have a count larger than one in a feature file
    Remove features that appear a low amount of times

    TODO: make a class to store unique_features to avoid passing it constantly
"""


import os
from collections import defaultdict 
import FeatureExtractor 

#ROOT_DIRECTORY = r'..\rextracted_features'
ROOT_DIRECTORY = r'..\dataset_features\subsets\2'
#OUT_DIRECTORY_CATEGORIZED = r"..\categorized_extracted_features"
OUT_DIRECTORY_CATEGORIZED = r"..\2_categorized_extracted_features"
OUT_DIRECTORY_REDUCED = r'..\reduced_extracted_features'
DIRECTORY_UNIQUE = r'unique_features'
DIRECTORY_BENIGN = r'benign_features'
DIRECTORY_MALICIOUS = r'malicious_features'

total_files = 0
TOTAL_FILES_NAME = r"total_files.txt"
file_totals = defaultdict(int)
FILE_TOTALS_NAME = r"file_totals.txt"

# TODO: Can cause problems with a small dataset, but likely will never be a problem
FLOOR_OFFSET = 5
CEIL_OFFSET = 1

URL_CATEGORIES = {
    'known_malware_paths': ['update_soft',           # lebar.gicp.net malware
                            'droid/app_v',           # hidroid.net APK dropper
                            'adreq/updateApp',       # winads.cn malware updater
                            'latest.php',            # C2 endpoint pattern
                            'order.php',             # C2 endpoint pattern
                            'hidroid.net/droid',     # Known malware server
                            'lebar.gicp.net/zj',     # Known C2 path
                            'winads.cn/adreq]'],     # Known malware adreq
    'c2_servers': ['lebar.gicp.net', 'master-code.ru', 'go108', 'anzhuo7', '5k3g', 'msreplier', 'hidroid'],
    'sms_fraud': ['nnetonline', 'sms', 'mms', 'monternet', 'zong'],
    'dynamic_dns': ['gicp.net', 'no-ip', 'dyndns', 'duckdns'],
    'vpon_specific': ['vpon.com'],
    'mydas_specific': ['mydas.mobi'],
    'wooboo_specific': ['wooboo'],
    'casee_specific': ['casee'],
    'webview_endpoints': ['webview', 'bridge', 'mraid', 'raid'],
    'chinese_domains_expanded': ['baidu', 'qq', 'sina', 'taobao', 'aliexpress', 'tmall', 'jd.com'],
    'adult': ['porn', 'youporn', 'xxx', 'adult', 'xvideo'],
    'ad_requests': ['ad', 'ads', 'getad', 'showad', 'click', 'impression', 'banner', 'interstitial'],
    'score_endpoints': ['score', 'leaderboard', 'rank', 'highscore', 'achievement'],
    'game_networks': ['gameloft', 'scoreloop', 'herocraft', 'glu', 'outfit7'],
    'tracking': ['log', 'track', 'event', 'metric'],
    'file_transfer': ['download', 'upload', 'file', 'apk', 'zip'],
    'config_endpoints': ['config', 'init', 'check', 'report', 'getinfo'],
    'static_content': ['static', 'image', 'images', 'img', 'css', 'js', 'resource', 'resources', 'asset', 'assets', 'content', 'lib', 'media', 'schema', 'schemas'],
    'app_dev': ['appspot', 'herokuapp', 'firebaseio', 'parseapp'],
    'api_calls': ['api', 'restserver', 'oauth', 'sdk', 'svc', 'service'],
    'media_files': ['.mp4', '.mp3', '.jpg', '.png', '.gif', '.xml', '.json', '.js', '.css'],
    'app_markets': ['play.google.com', 'market.android.com', 'amazon.comgpmas', '91.com'],
    'google_services': ['google', 'gstatic', 'googleapis', 'doubleclick', 'googlesyndication'],
    'facebook': ['facebook', 'fbcdn', 'graph.facebook'],
    'twitter': ['twitter', 'twimg', 't.twitter'],
    'microsoft': ['microsoft', 'azure', 'live', 'outlook', 'skype'],
    'amazon': ['amazonaws', 'amazon'],
}

# Single Feature File/Vector
def read_feature_file(file_path: str) -> dict[str: dict[str: int]]:
    """
        reads a feature file with no special processing
        counts how many features are in the file
    """
    features = FeatureExtractor.feature_dictionary()
    type_tag_pairs = dict(zip(FeatureExtractor.FEATURE_TAGS, FeatureExtractor.FEATURE_TYPES))

    try:
        with open(file_path, 'r', encoding= "utf-8", errors= "ignore") as features_file: 
            for feature in features_file: 
                feature_tag, _, body = feature.partition(": ")
                feature_and_count = body.split()
                if feature_tag in type_tag_pairs:
                    if len(feature_and_count) == 2: # if there is a count included
                        count = int(feature_and_count[1].strip()) # NOTE: strip() is just a precaution, split() should remove trailing whitespace
                    else:
                        count = 1 #otherwise default to 1
                    features[type_tag_pairs[feature_tag]][feature_and_count[0].strip()] = count
    except Exception as e:
         print(f"Error reading {file_path}: {e}")
    return features

#TODO: reconcile this and reload_unique_features (should do the same thing)
def read_unique_features(in_dir: str) -> dict[str, dict[str, int]]: # NOTE: can't use read_feature_file because it is meant to read full features
    """
    Reads unique feature files and creates a unique features dictionary
    """
    unique_features = FeatureExtractor.feature_dictionary()

    for feature_type, feature_tag in zip(FeatureExtractor.FEATURE_TYPES, FeatureExtractor.FEATURE_TAGS):
        file_name = f"unique_{feature_type}.txt" 
        file_path = os.path.join(in_dir, file_name) 
        if os.path.exists(file_path) and os.path.getsize(file_path): 
            try:
                with open(file_path, 'r', encoding= "utf-8", errors= "ignore") as unique_features_file: 
                    for feature in unique_features_file: 
                        feature_and_count = feature.removeprefix(f"{feature_tag}: ").split(" ") # Removes feature tag, splits feature into list of key and value
                        if len(feature_and_count) == 2: # if there is a count included
                            count = int(feature_and_count[1].strip()) 
                        else:
                            count = 1 #otherwise default to 1
                        unique_features[feature_type][feature_and_count[0].strip()] = count # Adds feature key and adds value as integer   
            except Exception as e:
                print(f"Error reading unique_features: {e}")
        else:
            print(f'INFO: {file_name} has not been created yet or was empty')
    return unique_features

def categorize_feature_file(file_path: str) -> dict[str: dict[str : int]]:
    """
        reads a feature file
        putting specific features in categories
        counting categories and singletons 
        storing relevant variables:
            total feature files
            total features
    """
    features = FeatureExtractor.feature_dictionary()

    try:
        with open(file_path, 'r', encoding= "utf-8", errors= "ignore") as features_file: 
            for feature in features_file: 
                for feature_type, feature_tag in zip(FeatureExtractor.FEATURE_TYPES, FeatureExtractor.FEATURE_TAGS): # NOTE: zip() returns a tuple containing the elements from each list that have the same indeces 
                    if feature.startswith(feature_tag): # Check each line to see which feature_type it belongs to
                        feature = feature.removeprefix(f"{feature_tag}: ").split(" ")[0] # Removes feature tag and potential value, stores feature
                        if (feature_type == FeatureExtractor.FEATURE_TYPES[3] or  
                            feature_type == FeatureExtractor.FEATURE_TYPES[4]): #APIs or Libraries
                            feature = level3_truncator(feature) #feature becomes the shortened version
                        elif feature_type == FeatureExtractor.FEATURE_TYPES[5]:#URLs
                            feature = find_categories(feature) #feature becomes the
                        features[feature_type][feature.strip()] += 1 # Adds feature key and adds value as integer 
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return features

def categorize_folder(in_dir: str, out_dir: str, unique_features: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """
        Reduces cardinality of a folder by categorizing feature files in it 
        NOTE: ONE FOLDER AT A TIME
        NEEDS TO DO BENIGN AND MALICIOUS SEPERATELY BECAUSE OF CURRENT FILE STRUCTURE
        Updates unique_features
        returns updated unique_features
    """
    global total_files

    if os.path.exists(in_dir): # Check if dir exists
        for _, _, filenames in os.walk(in_dir): 
            total_files += len(filenames) # Adds files to total number of files
            for filename in filenames: # For every file in directory
                in_file_path = os.path.join(in_dir, filename) # set in and out paths
                out_file_path = os.path.join(out_dir, filename)
                features = categorize_feature_file(in_file_path) # read the features
                write_feature_file(out_file_path, features) # write the features to the correct file, stores the count of each files total number of features to a dictionary
                unique_features = update_unique_features(features, unique_features) # update unique features
    else:
        print(f"Directory does not exist: {in_dir}\nSkipping")
    return unique_features

def write_feature_file(file_path: str, features: dict[str, dict[str, int]]):
    """
        writes one dictionary of features to a file
    """
    global file_totals
    
    try:
        with open(file_path, "w", encoding="utf-8", errors="ignore") as f:
            for feature_type, feature_tag in zip(FeatureExtractor.FEATURE_TYPES, FeatureExtractor.FEATURE_TAGS):
                for feature in features[feature_type]:
                    count = features[feature_type][feature]
                    file_totals[os.path.basename(file_path)] += count #Stores the total feature count for the file while writing
                    f.write(f"{feature_tag}: {feature.strip()} {count}\n")
    except Exception as e:
        print(f"Error Writing to file {file_path}\nException: {e}")

def level3_truncator(feature: str) -> str:
    """
        Truncates APIs and Libraries to the 3rd period
    """
    parts = feature.split(".")
    if len(parts) > 3:
        return (".").join(parts[:3]) # NOTE: [:3] get indeces until the third element
    return feature

def find_categories(url: str) -> str:
    """
        Returns the first category the url fits or the url if no category
    """
    url_lower = url.lower()
    main = url_lower.split('://', 1)[-1] if '://' in url_lower else url_lower
    parts = main.replace('?', '/').replace('&', '/').replace('=', '/').split('/')
    parts = [p for p in parts if p and len(p) > 1]
    
    for cat_name, keywords in URL_CATEGORIES.items():
        for keyword in keywords:
            for part in parts:
                if keyword in part:
                    return cat_name
    return url

# Unique Features
def update_unique_features(features: dict[str, dict[str, int]], unique_features: dict[str : defaultdict(int)]) -> dict[str, dict[str, int]]:
    """
        updates unique features from a new dictionary
        this version stores a count of each feature instance
        Cannot write to file as we go, because categories will be updated through out the reading process
    """
    for feature_type in features:
        for feature in features[feature_type]:
            unique_features[feature_type][feature] += features[feature_type][feature]
    return unique_features

def write_unique_features(out_dir: str, unique_features: dict[str : dict[str, int]]):
    """
        Writes unique feature file to directory, feature types remain seperate
    """

    if not os.path.exists(out_dir): # make the directory if it doesn't exist
            os.makedirs(out_dir)
    if len(unique_features) == len(FeatureExtractor.FEATURE_TAGS): # Confirm unique_features and FEATURE_TAGS are the same length
        for feature_type, feature_tag in zip(unique_features, FeatureExtractor.FEATURE_TAGS): # Iterate over feature_types and tags
            out_file = os.path.join(out_dir, f"unique_{feature_type}.txt") # For each type create the file of the same name
            try:
                with open(out_file, "w", encoding="utf-8", errors="ignore") as f: # try to open the file
                    for feature in unique_features[feature_type]: 
                        count = unique_features[feature_type][feature]
                        f.write(f"{feature_tag}: {feature.strip()} {count}\n") # Write each feature tag, count, and feature name
            except Exception as e:
                print(f"Error Writing to file {feature_type}.txt\nException: {e}")
    else:
        print(f"dictionary length mismatch:\nunique_features: {len(unique_features)}\nFEATURE_TAGS: {len(FeatureExtractor.FEATURE_TAGS)}")

# Feature Reduction
def reduce_unique_features(unique_features: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """
        Reads unique_features
        removes features from dictionary if they occur a small number of times, or if they appear in every file in the dataset
        places removed feature in new dictionary
        returns the reduced dictionary
    """
    reduced = FeatureExtractor.feature_dictionary()
    for feature_type in unique_features:
        for feature in unique_features[feature_type]:
            count = unique_features[feature_type][feature]
            if FLOOR_OFFSET < count < total_files - CEIL_OFFSET: 
                reduced[feature_type][feature] = unique_features[feature_type][feature]
            # TODO: Reduction of max length features DOES NOT take into account groups currently, 
            # there could technically be a group larger than the number of files that isn't used by every file 
            # this seems exceedingly unlikely but is still a bug
    return reduced

def reduce_feature_dict(unique_features: dict[str, dict[str, int]], features: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """
        Reduces a feature dictionary using the unique_features dictionary,
        only vectors that exist in the feature dict and the unique_feature dict are retained
        returns the reduced dictionary
    """
    reduced = FeatureExtractor.feature_dictionary()
    for feature_type in features:
        for feature in features[feature_type]:
            if feature in unique_features[feature_type].keys():
                reduced[feature_type][feature] = features[feature_type][feature]
    return reduced

def write_totals(out_dir: str):
    """
        writes total number of files to a .txt
        writes total features for each feature file to a list of all feature files
    """
    total_files_path = os.path.join(out_dir, TOTAL_FILES_NAME)
    file_totals_path = os.path.join(out_dir, FILE_TOTALS_NAME)
    try:
        with open(total_files_path, "w", encoding="utf-8", errors="ignore") as file: # Saves the total amount of files in the dataset, not really necessary to save but it doesn't hurt
            file.write(str(total_files))     
    except Exception as e:
        print(f"Error Writing Total Number of Files: {e}")     

    try:
        with open(file_totals_path, "w", encoding="utf-8", errors="ignore") as file: # Saves every feature file's total number of features (the sum of the counts)
            for feature_file in file_totals:
                 file.write(f"{feature_file}: {file_totals[feature_file]}\n")
    except Exception as e:
        print(f"Error Writing File Feature Totals: {e}") 

# Full Process
def catagorize_dataset(in_dir: str, out_dir: str):
    """
        Catagorizes an entire feature dataset and saves the results to another directory
    """
    global total_files # Number of files in dataset
    global file_totals # Number of features in a file (the sum of the counts)
    total_files = 0
    file_totals.clear()

    if os.path.exists(in_dir): # if we have the input directory
        in_benign = os.path.join(in_dir, DIRECTORY_BENIGN)
        in_malicious = os.path.join(in_dir, DIRECTORY_MALICIOUS)
        unique_features = FeatureExtractor.feature_dictionary() # Making a feature_dictionary

        out_benign = os.path.join(out_dir, DIRECTORY_BENIGN) 
        out_malicious = os.path.join(out_dir, DIRECTORY_MALICIOUS)
        out_unique = os.path.join(out_dir, DIRECTORY_UNIQUE) 

        # Must make folders if they don't exist TODO: add checks to sub functions
        if not os.path.exists(out_benign):
                    os.makedirs(out_benign)
        if not os.path.exists(out_malicious):
                    os.makedirs(out_malicious)
        if not os.path.exists(out_unique):
                    os.makedirs(out_unique)

        unique_features = categorize_folder(in_benign, out_benign, unique_features) #TODO: Make a class for unique features #TODO: what did I mean by this? the feature_dictionary() funciton??
        unique_features = categorize_folder(in_malicious, out_malicious, unique_features) # TODO: a class to encapsulate the unique features dictionary so it isn't global in feature extractor
        write_unique_features(out_unique, unique_features) # Also collects counts and adds to the total number of features for each file
        write_totals(out_dir) # Writes total number of files and the total number of features for each file
        print(f"Categorization Complete")
    else:
        print(f"Input directory does not exist: {in_dir}\nNo files Processed")

def reduce_dataset(in_dir: str, out_dir: str):
    """
        Removes features from the dataset that only appear a small number of times or appear in every feature file
    """
    # NOTE: TOTAL_FILES NEEDS TO BE RETRIEVED FROM THE PREVIOUS DATA SET
    global total_files
    global file_totals # Number of features in a file (the sum of the counts)
    file_totals.clear()

    in_unique = os.path.join(in_dir, DIRECTORY_UNIQUE)
    if os.path.exists(in_unique):
        if total_files < 1:
            total_files_path = os.path.join(in_dir, TOTAL_FILES_NAME)
            if os.path.exists(total_files_path):
                with open(total_files_path, 'r', encoding="utf-8", errors="ignore") as f:
                     total_files = int(f.read().strip())
            else:
                print(f"{total_files_path} does not exist.\nCannot reduce features")
                return()
        
        in_benign = os.path.join(in_dir, DIRECTORY_BENIGN)
        in_malicious = os.path.join(in_dir, DIRECTORY_MALICIOUS)
        
        out_benign = os.path.join(out_dir, DIRECTORY_BENIGN)
        out_malicious = os.path.join(out_dir, DIRECTORY_MALICIOUS)
        out_unique = os.path.join(out_dir, DIRECTORY_UNIQUE)

        if not os.path.exists(out_benign):
                        os.makedirs(out_benign)
        if not os.path.exists(out_malicious):
                        os.makedirs(out_malicious)
        if not os.path.exists(out_unique):
                        os.makedirs(out_unique)

        unique_features = read_unique_features(in_unique)
        reduced_unique = reduce_unique_features(unique_features)
        write_unique_features(out_unique, reduced_unique)
        total_files = 0 # NOTE: reset total_files for consistency and because write_totals saves total_files, best to count to be sure
        
        for source_dir, target_dir in ((in_benign, out_benign), (in_malicious, out_malicious)):
            if not os.path.exists(source_dir):
                continue
            for _, _, filenames in os.walk(source_dir):
                total_files += len(filenames)
                for filename in filenames:
                    in_file = os.path.join(source_dir, filename)
                    out_file = os.path.join(target_dir, filename)
                    try:
                        features = read_feature_file(in_file)
                        reduced_feats = reduce_feature_dict(reduced_unique, features)
                        write_feature_file(out_file, reduced_feats)
                    except Exception as e:
                        print(f"Error processing {in_file}: {e}")
                        continue
        write_totals(out_dir)
        print(f"Reduction Complete")
    else:
         print(f"Input directory does not exist: {in_dir}\nNo files Processed")
        
    #TODO: Store total features from each feature file

if __name__ == "__main__":
    print(f"Attempting to reduce cardinality of features in {ROOT_DIRECTORY}")
    print(f"Categorizing to {OUT_DIRECTORY_CATEGORIZED}")
    catagorize_dataset(ROOT_DIRECTORY, OUT_DIRECTORY_CATEGORIZED)
    #print(f"Reducing to {OUT_DIRECTORY_REDUCED}")
    #reduce_dataset(OUT_DIRECTORY_CATEGORIZED, OUT_DIRECTORY_REDUCED)