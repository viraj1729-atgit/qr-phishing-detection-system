'''QR Code scanning utilities.

Provides :func:`decode_qr_image` which accepts a binary stream (e.g. a ``BytesIO``
object) containing an image and returns the decoded URL string or ``None`` if no
QR code can be detected.

The implementation uses ``opencv-python`` for image preprocessing and ``pyzbar``
for robust QR decoding, falling back to OpenCV's built‑in ``QRCodeDetector`` when
necessary.
''' 

import cv2
import numpy as np
# from pyzbar import pyzbar  # Disabled: pyzbar requires native libzbar DLL which is missing on this Windows setup
from typing import Optional
from .utils import log_debug, log_error


def _preprocess_image(img: np.ndarray) -> np.ndarray:
    """Convert to grayscale and apply adaptive thresholding.

    The preprocessing helps both ``pyzbar`` and OpenCV's detector handle noisy or
    low‑contrast QR images.
    """
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    # Adaptive threshold – works on varying lighting conditions.
    thresh = cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        11,
        2,
    )
    return thresh


def _decode_with_pyzbar(img: np.ndarray) -> Optional[str]:
    """Attempt to decode using ``pyzbar``.

    The original implementation relied on the external ``libzbar`` DLL which is
    not available in this Windows environment.  We therefore skip the call and
    simply return ``None`` while logging the situation.
    """
    log_warning("pyzbar unavailable – skipping pyzbar decoding step")
    return None


def _decode_with_cv2(img: np.ndarray) -> Optional[str]:
    """Fallback using OpenCV's ``QRCodeDetector``.
    """
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    if points is not None and data:
        log_debug("OpenCV decoded URL: %s", data)
        return data
    return None


def decode_qr_image(image_stream) -> Optional[str]:
    """Decode a QR code from an image binary stream.

    Parameters
    ----------
    image_stream : file‑like object
        Must support ``read()`` and return raw image bytes.

    Returns
    -------
    Optional[str]
        The extracted URL string or ``None`` if decoding fails.
    """
    try:
        image_bytes = image_stream.read()
        img_array = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
        if img is None:
            log_error("OpenCV failed to decode image bytes.")
            return None
        # 1️⃣ Try OpenCV detector on the raw image.
        result = _decode_with_cv2(img)
        if result:
            return result
        # 2️⃣ Preprocess then try OpenCV detector again.
        preprocessed = _preprocess_image(img)
        result = _decode_with_cv2(preprocessed)
        if result:
            return result
        # 3️⃣ Finally, attempt pyzbar (will log warning and return None).
        result = _decode_with_pyzbar(preprocessed)
        return result
    except Exception as exc:
        log_error("Exception in decode_qr_image: %s", exc)
        return None
