import qrcode, pathlib, os

# URL to encode – you can change this to any test URL
url = "https://example.com/login"

# Destination inside the project data folder
out_path = pathlib.Path(r"C:\Users\VIRAJ DAREKAR\.gemini\antigravity\scratch\qr-phishing-detection-system\data\test-qrcode.png")
out_path.parent.mkdir(parents=True, exist_ok=True)

# Generate and save QR code image
img = qrcode.make(url)
img.save(out_path)
print(f"QR code saved to {out_path}")
