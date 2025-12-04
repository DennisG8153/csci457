#!/usr/bin/env python3
import sys
import os

def extract_api_superclass(line):
    if not line.startswith("API: "):
        return None
    full = line[5:].strip()
    if "(" in full:
        full = full.split("(")[0]
    parts = full.split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3])
    elif len(parts) == 2:
        return ".".join(parts)
    return parts[0]


def extract_intent_superclass(line):
    if not line.startswith("Intent: "):
        return None
    raw = line[8:].strip()
    lr = raw.lower()

    if raw.startswith("android.intent.action."):
        return "ACTION"
    if raw.startswith("android.intent.category."):
        return "CATEGORY"
    if "boot" in lr:
        return "BOOT_EVENT"
    if "sms" in lr:
        return "SMS_EVENT"
    if "phone" in lr or "call" in lr:
        return "PHONE_EVENT"
    if "service" in lr:
        return "SERVICE"
    return "OTHER_INTENT"


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

    ad_kws = ["adwo", "vpon", "mydas", "mopub", "startapp", "ju6666", "guohead"]
    if any(k in url for k in ad_kws):
        return "AD_NETWORK"

    if ".cn" in url:
        return "CHINA_NET"
    if ".mp4" in url or ".zip" in url:
        return "MEDIA_FILE"

    return "OTHER_URL"


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
    if "microphone" in hw:
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
    return "OTHER_HW"


def process_file(input_path, output_path):
    unique = set()

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            for extractor in (
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


def main(argv):
    # default expected filenames
    files = [
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
