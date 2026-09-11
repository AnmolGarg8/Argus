"""
Bonus Module: Attachment & QR Code Inspection
Inspects email attachments for:
  - Dangerous file extensions (.exe, .scr, .vbs, .bat, .js, .ps1, .hta, etc.)
  - Embedded QR codes in attached images (extracts URL and feeds into infrastructure_analysis)
"""

import os
import re
from typing import Union
from PIL import Image
from infrastructure_analysis import analyze_infrastructure

# Risky extensions frequently used in malware/droppers
SUSPICIOUS_EXTENSIONS = {
    ".exe": "Windows Executable Binary",
    ".scr": "Screen Saver Executable Dropper",
    ".js": "JavaScript Script File",
    ".vbs": "VBScript Automation File",
    ".bat": "Windows Batch Command File",
    ".cmd": "Windows Command Script",
    ".ps1": "PowerShell Script",
    ".hta": "HTML Application",
    ".iso": "Disk Image Container (often bypasses Mark-of-the-Web)",
    ".img": "Disk Image Container",
    ".dll": "Dynamic Link Library",
    ".wsf": "Windows Script File",
    ".jar": "Java Archive Executable",
}


def decode_qr_from_image(image_input: Union[str, Image.Image]) -> list[str]:
    """
    Attempt to detect and decode QR code contents from an image.
    Uses pyzbar if available; falls back to cv2 QRCodeDetector if available.
    """
    decoded_urls = []

    # Convert input to PIL Image if file-like or path
    pil_img = None
    if isinstance(image_input, Image.Image):
        pil_img = image_input
    elif hasattr(image_input, "read") or hasattr(image_input, "getvalue"):
        try:
            pil_img = Image.open(image_input)
        except Exception:
            pass
    elif isinstance(image_input, str) and os.path.exists(image_input):
        try:
            pil_img = Image.open(image_input)
        except Exception:
            pass

    # 1. Try pyzbar
    if pil_img is not None:
        try:
            from pyzbar.pyzbar import decode
            results = decode(pil_img)
            for r in results:
                text = r.data.decode("utf-8", errors="ignore")
                if text:
                    decoded_urls.append(text)
            if decoded_urls:
                return decoded_urls
        except BaseException:
            pass

    # 2. Try OpenCV QRCodeDetector fallback
    if pil_img is not None:
        try:
            import cv2
            import numpy as np
            cv_img = cv2.cvtColor(np.array(pil_img.convert("RGB")), cv2.COLOR_RGB2BGR)
            if cv_img is not None:
                detector = cv2.QRCodeDetector()
                val, pts, _ = detector.detectAndDecode(cv_img)
                if val:
                    decoded_urls.append(val)
            if decoded_urls:
                return decoded_urls
        except BaseException:
            pass

    # 3. If libraries unavailable or no QR found, check for embedded URL strings in binary metadata if path provided
    if isinstance(image_input, str) and os.path.exists(image_input):
        try:
            with open(image_input, "rb") as f:
                content = f.read(2048)
                matches = re.findall(rb"https?://[^\s\"'<>]+", content)
                for m in matches:
                    decoded_urls.append(m.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    return decoded_urls


def analyze_attachment(
    filename: str,
    file_bytes_or_path: Union[str, bytes, Image.Image] = None,
) -> dict:
    """
    Inspect attachment metadata, dangerous extension, and QR codes.

    Returns:
      {
        "flagged": bool,
        "signals": list[str],
        "confidence": float,
        "explanation": str,
        "qr_details": dict or None
      }
    """
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    signals = []
    confidence = 0.0
    explanations = []
    qr_details = None

    # Check extension
    if ext in SUSPICIOUS_EXTENSIONS:
        signals.append("SUSPICIOUS_EXECUTABLE_ATTACHMENT")
        confidence = max(confidence, 92.0)
        explanations.append(
            f"Attachment '{filename}' has a high-risk executable extension ({ext}: {SUSPICIOUS_EXTENSIONS[ext]})."
        )

    # Check for QR code in images
    is_image = ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"] or isinstance(file_bytes_or_path, Image.Image)

    if is_image and file_bytes_or_path:
        decoded = decode_qr_from_image(file_bytes_or_path)
        if decoded:
            extracted_url = decoded[0]
            signals.append("EMBEDDED_QR_CODE_DETECTED")
            confidence = max(confidence, 70.0)

            # Analyze extracted destination using infrastructure analysis
            infra_result = analyze_infrastructure(extracted_url)
            qr_details = {
                "decoded_data": extracted_url,
                "infrastructure_eval": infra_result,
            }

            if infra_result["flagged"]:
                signals.append("MALICIOUS_QR_DESTINATION")
                confidence = max(confidence, infra_result["confidence"])
                explanations.append(
                    f"QR code decoded into URL '{extracted_url}' which triggered infrastructure flags: {infra_result['explanation']}"
                )
            else:
                explanations.append(
                    f"QR code detected with destination '{extracted_url}' (infrastructure appears benign)."
                )

    flagged = len(signals) > 0
    if not flagged:
        confidence = 5.0
        explanation = f"Attachment '{filename}' passed security screening; no dangerous extensions or malicious QR payloads detected."
    else:
        explanation = " | ".join(explanations)

    return {
        "flagged": flagged,
        "signals": signals,
        "confidence": round(confidence, 1),
        "explanation": explanation,
        "qr_details": qr_details,
    }