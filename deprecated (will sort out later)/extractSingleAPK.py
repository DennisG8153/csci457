# extractSingleAPK
import os
import time
from collections import defaultdict, Counter
from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
import logging # want to surpress debug messages but it is currently not working
import tqdm 

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.basicConfig(
    filename='androguard.log',   
    filemode='w',               
    level=logging.DEBUG,         
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

logging.getLogger('androguard').setLevel(logging.WARNING)
logging.getLogger().setLevel(logging.WARNING)

APK_SOURCE = r'D:\Senior Project 2 CSCI-457\Datasets\amd_data\DroidKungFu\variety2\0a34d14be275ef9fc3227716a5c3b85b.apk'

if not os.path.exists(APK_SOURCE):
    print(f"Error: Folder '{APK_SOURCE}' does not exist!")
    exit()

start_time = time.time()

#permission_counter = defaultdict(int)
#api_call_counter = defaultdict(int)

try:
    apk = APK(APK_SOURCE)
    perms = str(apk.get_permissions())
    print(perms)

except Exception as e:
    print(f"Error processing {APK_SOURCE}: {e}")



elapsed_time1 = time.time() - start_time


start_time = time.time()

try:
    a, d, dx = AnalyzeAPK(APK_SOURCE)
    perms = str(a.get_permissions())
    print(perms)

except Exception as e:
    print(f"Error processing {APK_SOURCE}: {e}")

elapsed_time = time.time() - start_time
print(f"Time taken: {elapsed_time1:.2f} seconds")
print(f"Time taken: {elapsed_time:.2f} seconds")