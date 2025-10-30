import requests
import os
import pandas as pd

# --- Configuration ---
API_KEY = "90e22d1735865f252b1a82b59c0d036782b73a92ef36f9e636cb36d00709153c"  # IMPORTANT: Replace with your actual API key
DOWNLOAD_LIMIT_BENIGN = 50  # Number of benign apps to download
DOWNLOAD_LIMIT_MALICIOUS = 50  # Number of malicious apps to download
APK_SAVE_DIRECTORY = "apk_collection"  # Folder to save the downloaded APKs
CSV_OUTPUT_FILE = "amd_dataset.csv"  # The CSV file this script will generate

def download_apk(sha256, save_path):
    """Downloads a single APK from AndroZoo given its SHA256 hash."""
    if os.path.exists(save_path):
        print(f"Skipping {sha256}, already exists.")
        return True

    print(f"Downloading {sha256}...")
    url = f"https://androzoo.uni.lu/api/download?apikey={API_KEY}&sha256={sha256}"
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        with open(save_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Successfully downloaded {sha256}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to download {sha256}. Error: {e}")
        return False

def get_latest_samples(is_malicious=False):
    """Fetches the latest sample metadata from AndroZoo."""
    # We query for apps with a high number of positive detections for malware,
    # or zero detections for benign apps.
    vt_detection_threshold = ">10" if is_malicious else "0"
    limit = DOWNLOAD_LIMIT_MALICIOUS if is_malicious else DOWNLOAD_LIMIT_BENIGN

    print(f"Fetching {'malicious' if is_malicious else 'benign'} samples from AndroZoo...")
    url = f"https://androzoo.uni.lu/api/search?apikey={API_KEY}&query=vt_detection:{vt_detection_threshold}&limit={limit}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch samples. Error: {e}")
        return None

def main():
    """Main function to orchestrate the download and CSV creation."""
    if API_KEY == "YOUR_ANDROZOO_API_KEY_HERE":
        print("ERROR: Please replace 'YOUR_ANDROZOO_API_KEY_HERE' with your actual API key in the script.")
        return

    # Create the directory to store APKs if it doesn't exist
    os.makedirs(APK_SAVE_DIRECTORY, exist_ok=True)

    all_samples = []

    # Get and download malicious samples
    malicious_samples = get_latest_samples(is_malicious=True)
    if malicious_samples:
        for sample in malicious_samples.get("results", []):
            sha256 = sample.get("sha256")
            if sha256:
                save_path = os.path.join(APK_SAVE_DIRECTORY, f"{sha256}.apk")
                if download_apk(sha256, save_path):
                    # Add to our list for the CSV, with label 1 for malicious
                    all_samples.append({"sha256": sha256, "label": 1})

    # Get and download benign samples
    benign_samples = get_latest_samples(is_malicious=False)
    if benign_samples:
        for sample in benign_samples.get("results", []):
            sha256 = sample.get("sha256")
            if sha256:
                save_path = os.path.join(APK_SAVE_DIRECTORY, f"{sha256}.apk")
                if download_apk(sha256, save_path):
                    # Add to our list for the CSV, with label 0 for benign
                    all_samples.append({"sha256": sha256, "label": 0})

    # Create the DataFrame and save it to CSV
    if not all_samples:
        print("No samples were downloaded. The CSV file will not be created.")
        return

    df = pd.DataFrame(all_samples)
    df.to_csv(CSV_OUTPUT_FILE, index=False)
    print(f"\nSuccessfully created dataset '{CSV_OUTPUT_FILE}' with {len(all_samples)} entries.")
    print(f"All APKs are saved in the '{APK_SAVE_DIRECTORY}' folder.")

if __name__ == "__main__":
    main()
