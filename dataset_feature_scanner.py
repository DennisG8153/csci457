import os
from androguard.misc import AnalyzeAPK

# --- Configuration based on the Rough Plan ---

# Define sensitive API prefixes that should NOT be collapsed
SENSITIVE_PREFIXES = (
    "android.telephony",
    "android.location",
    "android.net",
    "android.accounts",
    "android.provider.ContactsContract",
    "android.webkit",
    "android.app.admin",
    "android.content.ClipboardManager",
    "java.net",          # For network activity
    "java.io",           # For file system access
    "javax.crypto",      # For encryption/decryption
)

# Define common, non-sensitive UI/UX packages to collapse to their parent
PACKAGE_COLLAPSE = (
    "android.graphics",
    "android.view",
    "android.widget",
    "android.os",
    "android.content",   # General app components
    "android.util",      # Utility classes
    "java.lang",         # Core Java language features
    "java.util",         # Core Java utility classes
)

def process_api_call(full_api_call):
    """
    Processes a full API call according to the logic in the rough plan.
    - Keeps sensitive API calls in full detail.
    - Collapses common, non-sensitive API calls to their package name.
    - Ignores others.
    """
    # Check if the API call belongs to a sensitive category
    for prefix in SENSITIVE_PREFIXES:
        if full_api_call.startswith(prefix):
            return full_api_call  # Keep the full, detailed API call

    # Check if the API call belongs to a common, collapsible category
    for prefix in PACKAGE_COLLAPSE:
        if full_api_call.startswith(prefix):
            # Collapse it to its superclass/package name (e.g., "android.widget.Button.setText" -> "android.widget")
            return prefix

    # If the call is neither sensitive nor common/collapsible, we can choose to ignore it
    # to keep the feature set focused. For now, let's return None.
    return None

# --- Main Script Logic ---

apk_root_folder = "amd_data"  # or whatever the root folder for apks is called

#set only holds unique values, no duplicates
unique_permissions = set()
unique_api_calls = set()

# Check if the APK folder exists
if not os.path.isdir(apk_root_folder):
    print(f"Error: The directory '{apk_root_folder}' was not found.")
    print("Please create it and place your APK files inside.")
else:
    #iterate through all apks in the folder and subfolders
    for root, dirs, files in os.walk(apk_root_folder):
        for apk_file in files:
            if apk_file.endswith(".apk"): #only care about .apk files
                apk_path = os.path.join(root, apk_file) #full path to the apk
                print(f"Processing: {apk_file}")
                try:
                    #analyze the apk
                    a, d, dx = AnalyzeAPK(apk_path)
                    # Collect permissions
                    unique_permissions.update(a.get_permissions())
                    # Collect and process API calls
                    for method in dx.get_methods():
                        #iterate through all calls in the method
                        for _, call, _ in method.get_xref_to():
                            #code readability
                            classname = call.class_name[1:-1].replace(
                                "/", ".")  # Remove leading 'L' and trailing ';'
                            methodname = call.name
                            full_api_call = f"{classname}.{methodname}"

                            # Only consider java and android api calls
                            if classname.startswith("android.") or classname.startswith("java."):
                                processed_call = process_api_call(full_api_call)
                                if processed_call:  # Add the call only if it's not None
                                    unique_api_calls.add(processed_call)

                except Exception as e:
                    print(f"  -> Error processing {apk_file}: {e}")

# Save unique permissions to a text file, one per line
with open("unique_permissions.txt", "w", encoding="utf-8") as perm_file:
    for perm in sorted(unique_permissions):
        perm_file.write(f"{perm}\n")

# Save unique API calls to a text file, one per line
with open("unique_api_calls_processed.txt", "w", encoding="utf-8") as api_file:
    for api in sorted(unique_api_calls):
        api_file.write(f"{api}\n")

print("\nScan complete.")
print(f"Found {len(unique_permissions)} unique permissions, saved to 'unique_permissions.txt'")
print(f"Found {len(unique_api_calls)} processed unique API calls, saved to 'unique_api_calls_processed.txt'")
