import os
import json
import urllib.request

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "enterprise-attack.json")

def download_stix():
    print(f"Downloading MITRE ATT&CK STIX bundle from {STIX_URL}...")
    os.makedirs(DATA_DIR, exist_ok=True)
    urllib.request.urlretrieve(STIX_URL, OUTPUT_FILE)
    print(f"Successfully downloaded to {OUTPUT_FILE}")

if __name__ == "__main__":
    download_stix()
