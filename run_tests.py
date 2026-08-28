import requests
import json
import glob
import os

print("Starting YaraTrix Real-World Engine Test...\n")

test_files = glob.glob('test_suite/*')
test_files = [f for f in test_files if os.path.isfile(f) and not f.endswith('README.md')]

for filepath in test_files:
    print(f"[*] Scanning: {os.path.basename(filepath)}")
    try:
        with open(filepath, 'rb') as f:
            files = {'file': (os.path.basename(filepath), f)}
            # The endpoint seems to be just /scan based on main.py analysis earlier
            # But let me try /scan first. The FastAPI backend is running on 8000.
            response = requests.post('http://127.0.0.1:8000/scan', files=files)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                intel = data.get('intelligence', {})
                
                if matches:
                    print(f"   [!] THREAT DETECTED: {len(matches)} Rule(s) Triggered")
                    print(f"       Threat Level: {intel.get('threat_level', 'unknown').upper()}")
                    print(f"       Tactics: {', '.join(intel.get('tactic_coverage', []))}")
                    for m in matches:
                        print(f"         - {m.get('rule_name')} (Severity: {m.get('severity')})")
                else:
                    print("   [+] CLEAN: No threats detected.")
            else:
                print(f"   [x] Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"   [x] Request failed: {e}")
    print("-" * 50)
