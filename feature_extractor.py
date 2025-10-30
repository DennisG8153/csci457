import os
import re
import subprocess
import zipfile
import io
import shutil
import hashlib
import json
from multiprocessing import Process, Queue
from lxml import etree
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.misc import AnalyzeAPK
from data_structures import StaticFeatures, BinaryFeatures

def unpack_apk(apk_path: str, output_dir: str) -> bool:
    """
    Unpacks an Android Application Package (APK) file into a specified output directory
    using the `apktool` command-line utility.
    """
    try:
        # 使用 java 直接运行 apktool.jar
        result = subprocess.run(["java", "-jar", "C:\\Windows\\apktool\\apktool.jar", 
                       "d", "-f", apk_path, "-o", output_dir], 
                      capture_output=True, text=True, timeout=300)  # 5 minute timeout
        if result.returncode != 0:
            print(f"Error: APKtool failed to unpack {apk_path}")
            print(f"APKtool stderr: {result.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"Error: APKtool timed out while unpacking {apk_path}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error: APKtool failed to unpack {apk_path}")
        print(f"APKtool error: {e}")
        return False
    except FileNotFoundError:
        print("Error: Java or APKtool not found. Please ensure they are installed and in PATH.")
        return False
    except Exception as e:
        print(f"Unexpected error while unpacking APK: {e}")
        return False

def extract_static_features(decompiled_apk_dir: str) -> StaticFeatures:
    """
    Extracts static features from the decompiled APK directory.
    This includes information from the AndroidManifest.xml, Smali files, and other resources.

    Args:
        decompiled_apk_dir (str): The absolute path to the directory containing the
                                decompiled APK files.

    Returns:
        StaticFeatures: A dataclass instance containing all extracted static features.
    """
    manifest_path = os.path.join(decompiled_apk_dir, "AndroidManifest.xml")
    try:
        # Parse the AndroidManifest.xml file using lxml for easy XML navigation.
        tree = etree.parse(manifest_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing AndroidManifest.xml: {e}")
        return StaticFeatures(permissions=[], apis=[], urls=[], components={}, manifest_info={}, intent_filters={})
    
    # Extract permissions declared in the manifest (e.g., <uses-permission android:name="..."/>).
    permissions = [p.get('{http://schemas.android.com/apk/res/android}name') for p in root.findall('.//uses-permission')]
    
    # Extract components: activities, services, receivers, and providers declared in the manifest.
    # The 'name' attribute typically holds the fully qualified class name.
    components = {
        'activities': [a.get('{http://schemas.android.com/apk/res/android}name') for a in root.findall('.//activity')],
        'services': [s.get('{http://schemas.android.com/apk/res/android}name') for s in root.findall('.//service')],
        'receivers': [r.get('{http://schemas.android.com/apk/res/android}name') for r in root.findall('.//receiver')],
        'providers': [p.get('{http://schemas.android.com/apk/res/android}name') for p in root.findall('.//provider')]
    }

    # Extract URLs from all relevant files within the decompiled APK directory.
    # This includes Smali, XML, HTML, and JavaScript files, which may contain hardcoded URLs.
    urls = set()
    for root_dir, _, files in os.walk(decompiled_apk_dir):
        for file in files:
            if file.endswith(('.smali', '.xml', '.html', '.js')):
                file_path = os.path.join(root_dir, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Regular expression to find common HTTP/HTTPS URL patterns.
                        found_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', content)
                        urls.update(found_urls)
                except Exception:
                    # Ignore files that cannot be read or processed.
                    continue

    # Extract Android API calls directly from Smali files.
    # Smali code often reveals direct invocations of system APIs.
    apis = set()
    smali_dir = os.path.join(decompiled_apk_dir, "smali")
    if os.path.exists(smali_dir):
        for root_dir, _, files in os.walk(smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = os.path.join(root_dir, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # Regex to find 'invoke-' instructions calling Android framework methods.
                            found_apis = re.findall(r'invoke-\w+ {.*}, Landroid/[\w/]+;->\w+\(.*\)', content)
                            apis.update(found_apis)
                    except Exception:
                        # Ignore smali files that cause read/regex errors.
                        continue

    # Extract intent filters for each component (activity, service, receiver).
    # Intent filters define how components respond to system or app-generated intents.
    intent_filters = {}
    for component_type in ['activity', 'service', 'receiver']:
        for component in root.findall(f'.//{component_type}'):
            comp_name = component.get('{http://schemas.android.com/apk/res/android}name')
            filters = component.findall('.//intent-filter')
            if comp_name and filters:
                intent_filters[comp_name] = []
                for f in filters:
                    actions = [a.get('{http://schemas.android.com/apk/res/android}name') for a in f.findall('.//action')]
                    categories = [c.get('{http://schemas.android.com/apk/res/android}name') for c in f.findall('.//category')]
                    intent_filters[comp_name].append({'actions': actions, 'categories': categories})
    
    # Extract general manifest information like package name and version details.
    manifest_info = {
        'package_name': root.get('package'),
        'version_code': root.get('{http://schemas.android.com/apk/res/android}versionCode'),
        'version_name': root.get('{http://schemas.android.com/apk/res/android}versionName'),
    }

    return StaticFeatures(
        permissions=permissions, 
        apis=list(apis), 
        urls=list(urls), 
        components=components, 
        manifest_info=manifest_info,
        intent_filters=intent_filters
    )


def _execute_binary_analysis_process(apk_path: str, result_queue: Queue):
    """
    Helper function to run the slow Androguard analysis in a separate process.
    The result is put into a queue to be retrieved by the main process.
    """
    try:
        a_obj, d_objs, x_obj = AnalyzeAPK(apk_path)

        # This is a simplified version of the original extraction logic.
        # It can be expanded if more detailed features are needed.
        raw_strings = list(a_obj.get_strings()) if hasattr(a_obj, 'get_strings') else []

        api_calls_sequences = []
        for d in d_objs if isinstance(d_objs, list) else [d_objs]:
            for method in d.get_methods():
                try:
                    method_analysis = x_obj.get_method_analysis(method)
                    if method_analysis:
                        method_api_calls = [
                            f"{callee.get_class_name()}->{callee.get_name()}"
                            for _, callee, _ in method_analysis.get_xref_to()
                            if callee.get_class_name().startswith('Landroid/')
                        ]
                        if method_api_calls:
                            api_calls_sequences.append(method_api_calls)
                except Exception:
                    continue

        result = BinaryFeatures(
            api_calls_sequences=api_calls_sequences,
            raw_strings=raw_strings,
            call_graph_summary={}  # Call graph is too slow, so we skip it here.
        )
        result_queue.put(result)
    except Exception as e:
        # If any error occurs in the subprocess, put the error in the queue.
        result_queue.put(e)

def extract_binary_features(apk_path: str) -> BinaryFeatures:
    """
    Extracts binary features from the raw APK file using Androguard.
    This function runs the analysis in a separate process with a 5-minute timeout
    to prevent the main application from hanging on complex APK files.
    """
    q = Queue()
    p = Process(target=_execute_binary_analysis_process, args=(apk_path, q))
    p.start()

    # Wait for the process to complete, with a timeout of 300 seconds (5 minutes).
    p.join(timeout=300)

    if p.is_alive():
        # If the process is still alive after the timeout, terminate it.
        print("Binary analysis timed out after 5 minutes. Terminating process.")
        p.terminate()
        p.join()  # Ensure the process is fully cleaned up.
        # Return empty features as a fallback.
        return BinaryFeatures(api_calls_sequences=[], raw_strings=[], call_graph_summary={})

    try:
        # Get the result from the queue.
        result = q.get_nowait()
        if isinstance(result, Exception):
            print(f"An error occurred during binary analysis: {result}")
            return BinaryFeatures(api_calls_sequences=[], raw_strings=[], call_graph_summary={})
        return result
    except Exception:
        # If the queue is empty or another error occurs, return empty features.
        print("Failed to retrieve result from binary analysis process.")
        return BinaryFeatures(api_calls_sequences=[], raw_strings=[], call_graph_summary={})