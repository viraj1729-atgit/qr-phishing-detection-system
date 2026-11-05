import qrcode, pathlib, os

# Malicious URL with multiple heuristic flags:
# - IP address in host
# - Known shortener (bit.ly)
# - Long URL (excessive length)
# - Hyphens in path (many_hyphens)
# - Suspicious TLD (we'll use .xyz to also trigger suspicious_tld)
url = "http://192.168.1.200/login-page-with-many-hyphens-and-a-really-long-parameter?ref=bit.ly/evil&extra=" + "a"*80 + ".xyz"

out_path = pathlib.Path(r"C:\Users\VIRAJ DAREKAR\.gemini\antigravity\scratch\qr-phishing-detection-system\data\malicious_qr.png")
out_path.parent.mkdir(parents=True, exist_ok=True)

img = qrcode.make(url)
img.save(out_path)
print(f"Malicious QR saved to {out_path}")
