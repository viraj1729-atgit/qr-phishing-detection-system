'''Streamlit dashboard for QR Phishing Detection.

The UI lets the user upload an image (or capture via webcam – not implemented here),
decodes the QR code, runs the heuristic analysis, and displays the result with a
risk gauge and a table of flagged features.
''' 

import streamlit as st
from pathlib import Path
import io
import sys, os

# Ensure the project root (one level up) is on the import path so we can import the
# backend package when the script is executed from the `frontend` subdirectory.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

# Import backend logic directly – this runs in the same process.
from backend.scanner import decode_qr_image
from backend.analyzer import analyze_url, RiskLevel

st.set_page_config(page_title="QR Phishing Detector", layout="centered")
st.title("🔍 QR Code Phishing Detection")
st.write(
    "Upload a QR code image (PNG/JPEG/WEBP). The app will decode the URL, "
    "run heuristic checks and show a risk score."
)

uploaded_file = st.file_uploader("Choose an image", type=["png", "jpg", "jpeg", "webp"])

if uploaded_file:
    # Show the image – ensure a displayable format (convert to RGB if needed)
    image_bytes = uploaded_file.read()
    # Load with Pillow, convert to RGB if necessary
    from PIL import Image
    pil_img = Image.open(io.BytesIO(image_bytes))
    if pil_img.mode != "RGB":
        pil_img = pil_img.convert("RGB")
    st.image(pil_img, caption="Uploaded QR code", width='stretch')
    # Re‑encode to PNG (a format OpenCV handles reliably) and create a fresh BytesIO stream
    buf = io.BytesIO()
    pil_img.save(buf, format='PNG')
    buf.seek(0)
    image_stream = buf
    # Decode using the backend scanner
    decoded_url = decode_qr_image(image_stream)
    if not decoded_url:
        st.error("❌ No QR code could be decoded from the image.")
    else:
        st.success(f"✅ Decoded URL: {decoded_url}")
        # Analyse
        result = analyze_url(decoded_url)
        # Risk gauge
        risk_color = {
            RiskLevel.SAFE: "green",
            RiskLevel.SUSPICIOUS: "orange",
            RiskLevel.MALICIOUS: "red",
        }[result.level]
        st.metric(label="Risk Score", value=f"{result.score}%", delta=result.level.value.title())
        st.progress(result.score / 100)
        st.markdown(f"**Risk level:** <span style='color:{risk_color}'>{result.level.value.title()}</span>", unsafe_allow_html=True)
        # Feature table
        st.subheader("Heuristic Flags")
        flagged = {k: v for k, v in result.features.items() if v}
        if flagged:
            st.table(flagged)
        else:
            st.info("No suspicious heuristics were triggered.")
