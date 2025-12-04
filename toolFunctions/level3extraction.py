#!/usr/bin/env python3
import sys
import os

# -------------------------
# Library: Level 4 (full package name)
# -------------------------
def extract_library_superclass(line):
    if not line.startswith("Library: "):
        return None
    full = line[9:].strip()
    return full  # full package name for max detection capability

# -------------------------
# API: Level 4 (full name)
# -------------------------
def extract_api_superclass(line):
    if not line.startswith("API: "):
        return None
    full = line[5:].strip()
    if "(" in full:
        full = full.split("(")[0]
    return full  # keep full qualified API name for max detection capability

# -------------------------
# Intent: Level 3 (action/category + sensitive flags)
# -------------------------
SENSITIVE_INTENTS = {
    "android.intent.action.BOOT_COMPLETED": "BOOT_EVENT",
    "android.intent.action.SMS_RECEIVED": "SMS_EVENT",
    "android.intent.action.PACKAGE_ADDED": "PACKAGE_EVENT",
    "android.intent.action.PACKAGE_REMOVED": "PACKAGE_EVENT",
}

def extract_intent_superclass(line):
    if not line.startswith("Intent: "):
        return None
    raw = line[8:].strip()
    if raw in SENSITIVE_INTENTS:
        return SENSITIVE_INTENTS[raw]
    if raw.startswith("android.intent.action."):
        return "ACTION"
    if raw.startswith("android.intent.category."):
        return "CATEGORY"
    return "OTHER_INTENT"

# -------------------------
# Permissions: Level 1 risk-based
# -------------------------
def extract_permission_superclass(line):
    if not line.startswith("Permission: "):
        return None
    p = line[12:].strip().upper()

    if "SMS" in p:
        return "SMS_TELEPHONY"
    if "LOCATION" in p:
        return "LOCATION"
    if "CAMERA" in p or "VIDEO" in p:
        return "CAMERA"
    if "AUDIO" in p or "MICROPHONE" in p:
        return "AUDIO"
    if "WIFI" in p or "NETWORK" in p:
        return "NETWORK"
    if "BLUETOOTH" in p:
        return "BLUETOOTH"
    if "STORAGE" in p:
        return "STORAGE"
    if "SYSTEM" in p or "ALERT" in p:
        return "SYSTEM_PRIVILEGE"
    return "OTHER_PERMISSION"

# -------------------------
# URLs: Level 1 risk-based
# -------------------------
AD_KEYWORDS = ["adwo", "vpon", "mydas", "mopub", "startapp", "ju6666", "guohead"]

def extract_url_superclass(line):
    if not line.startswith("URL: "):
        return None
    url = line[5:].strip().lower()

    if "localhost" in url:
        return "LOCALHOST"
    if url.startswith("http://192.") or url.startswith("http://10.") or url.startswith("http://172."):
        return "PRIVATE_IP"
    if "google" in url:
        return "GOOGLE"
    if any(k in url for k in AD_KEYWORDS):
        return "AD_NETWORK"
    if ".cn" in url:
        return "CHINA_NET"
    if ".mp4" in url or ".zip" in url:
        return "MEDIA_FILE"
    return "OTHER_URL"

# -------------------------
# Hardware: Raw + functional
# -------------------------
def extract_hw_superclass(line):
    if not line.startswith("Used Hardware/Software: "):
        return None
    hw = line[24:].strip().lower()

    if "location" in hw:
        return "LOCATION"
    if "sensor" in hw or "accelerometer" in hw:
        return "SENSORS"
    if "camera" in hw:
        return "CAMERA"
    if "microphone" in hw or "audio" in hw:
        return "AUDIO"
    if "bluetooth" in hw:
        return "BLUETOOTH"
    if "telephony" in hw:
        return "TELEPHONY"
    if "wifi" in hw:
        return "NETWORK"
    if "touch" in hw:
        return "INPUT"
    if "screen" in hw or "display" in hw:
        return "DISPLAY"
    return hw.upper()  # raw hardware/software name for max detection capability

# -------------------------
# File processing
# -------------------------
def process_file(input_path, output_path):
    unique = set()

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            for extractor in (
                extract_library_superclass,   # <-- added
                extract_api_superclass,
                extract_intent_superclass,
                extract_permission_superclass,
                extract_url_superclass,
                extract_hw_superclass
            ):
                key = extractor(line)
                if key:
                    unique.add(key)
                    break

    with open(output_path, "w", encoding="utf-8") as out:
        for s in sorted(unique):
            out.write(s + "\n")

# -------------------------
# Main
# -------------------------
def main(argv):
    files = [
    "unique_libraries.txt",      # <-- added
    "unique_api_calls.txt",
    "unique_intents.txt",
    "unique_permissions.txt",
    "unique_urls.txt",
    "unique_used_hsware.txt"
]

    for path in files:
        if os.path.exists(path):
            out = path.replace(".txt", "_superclasses.txt")
            process_file(path, out)
            print(f"✔ Generated {out}")
        else:
            print(f"✖ Missing: {path}")

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
