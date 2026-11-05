import sys, pathlib
import os
# Add project root to path
PROJECT_ROOT = pathlib.Path(r'C:\Users\VIRAJ DAREKAR\.gemini\antigravity\scratch\qr-phishing-detection-system')
sys.path.append(str(PROJECT_ROOT))
from backend.scanner import decode_qr_image
p = PROJECT_ROOT / 'data' / 'malicious_qr.png'
with open(p, 'rb') as f:
    url = decode_qr_image(f)
print('Decoded URL:', url)
