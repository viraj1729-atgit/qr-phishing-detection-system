'''Backend API for QR Phishing Detection System

Provides a FastAPI server exposing an endpoint ``/api/scan`` that accepts an image file,
decodes the QR code, analyzes the embedded URL and returns a JSON report.
''' 

import io
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST

from .scanner import decode_qr_image
from .analyzer import analyze_url, RiskLevel

app = FastAPI(title="QR Phishing Detection API")

@app.post("/api/scan")
async def scan_qr(file: UploadFile = File(...)):
    """Accept an image, decode QR, analyse URL and return a risk report.

    Returns
    -------
    JSON response with keys:
        - ``decoded_url``: extracted URL string (or ``null`` if decoding failed)
        - ``risk_level``: one of ``"safe"``, ``"suspicious"`` or ``"malicious"``
        - ``risk_score``: integer 0‑100
        - ``heuristics``: dict of individual feature flags
    """
    if file.content_type not in ["image/png", "image/jpeg", "image/jpg", "image/webp"]:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Unsupported file type. Please upload PNG, JPEG or WEBP.")
    try:
        image_bytes = await file.read()
        image_stream = io.BytesIO(image_bytes)
        decoded_url = decode_qr_image(image_stream)
        if decoded_url is None:
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="No QR code detected.")
        analysis = analyze_url(decoded_url)
        response = {
            "decoded_url": decoded_url,
            "risk_level": analysis.level.value,
            "risk_score": analysis.score,
            "heuristics": analysis.features,
        }
        return JSONResponse(content=response)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
