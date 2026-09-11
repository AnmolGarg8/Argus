"""
Visual & Behavioral — Page Similarity Module
Uses perceptual hashing (imagehash + Pillow) to detect visual brand impersonation
by comparing a given screenshot against reference login-page templates.

LIMITATION NOTE:
Capturing live web page screenshots requires heavyweight headless browser dependencies
(such as Playwright or Selenium with Chromium/Geckodriver binaries). To preserve portable,
zero-dependency hackathon execution across any OS, this module accepts a pre-supplied
screenshot path or a PIL Image object directly as input.
"""

import os
from typing import Union
from PIL import Image

try:
    import imagehash
except ImportError:
    imagehash = None


class _FallbackHash:
    """Fallback 64-bit difference hash when imagehash wheel is unavailable."""
    def __init__(self, bits: list):
        self.bits = bits
    def __sub__(self, other):
        if hasattr(other, 'bits'):
            return sum(b1 != b2 for b1, b2 in zip(self.bits, other.bits))
        return 64


def _calc_dhash(img: Image.Image, hash_size: int = 8) -> _FallbackHash:
    """Pure-Python difference hash (dHash) using standard Pillow resizing."""
    resized = img.convert("L").resize((hash_size + 1, hash_size))
    pixels = list(resized.getdata())
    bits = []
    for r in range(hash_size):
        for c in range(hash_size):
            bits.append(pixels[r * (hash_size + 1) + c] > pixels[r * (hash_size + 1) + c + 1])
    return _FallbackHash(bits)


# Directory containing reference brand templates
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates", "reference_logins")


def load_reference_hashes(template_dir: str = TEMPLATES_DIR) -> dict:
    """
    Precompute and return perceptual hashes for all reference templates in directory.
    Returns: {brand_name: {'phash': ImageHash, 'dhash': ImageHash, 'path': str}}
    """
    ref_hashes = {}
    if not os.path.exists(template_dir):
        return ref_hashes

    for fname in os.listdir(template_dir):
        if fname.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            brand_name = os.path.splitext(fname)[0].replace("_", " ").title()
            fpath = os.path.join(template_dir, fname)
            try:
                with Image.open(fpath) as img:
                    # Convert to RGB to ensure uniform color space
                    img_rgb = img.convert("RGB")
                    if imagehash is not None:
                        p_h = imagehash.phash(img_rgb)
                        d_h = imagehash.dhash(img_rgb)
                    else:
                        d_h = _calc_dhash(img_rgb)
                        p_h = d_h
                    ref_hashes[brand_name] = {
                        "phash": p_h,
                        "dhash": d_h,
                        "path": fpath,
                        "filename": fname,
                    }
            except Exception:
                continue
    return ref_hashes


def compute_visual_similarity(hash1, hash2, max_bits: int = 64) -> float:
    """
    Compute percentage similarity (0-100) from Hamming distance between two image hashes.
    """
    hamming_dist = hash1 - hash2  # subtraction computes Hamming distance in imagehash
    # Normalize: 0 distance = 100% similarity, max_bits distance = 0% similarity
    similarity = max(0.0, (1.0 - (hamming_dist / max_bits))) * 100.0
    return round(similarity, 2)


def analyze_page_similarity(
    image_input: Union[str, Image.Image],
    threshold: float = 75.0,
    template_dir: str = TEMPLATES_DIR,
) -> dict:
    """
    Analyze an uploaded screenshot or image path against reference brand templates.

    Parameters:
      image_input: File path (str) or PIL Image instance.
      threshold: Minimum similarity percentage (0-100) to trigger an impersonation flag.
      template_dir: Path to directory containing baseline template images.

    Returns:
      {
        "flagged": bool,
        "signals": list[str],
        "confidence": float,
        "explanation": str,
        "matched_brand": str or None,
        "similarity_score": float,
        "all_matches": list[dict]
      }
    """
    if isinstance(image_input, str):
        if not os.path.exists(image_input):
            return {
                "flagged": False,
                "signals": [],
                "confidence": 0.0,
                "explanation": f"Screenshot file not found at: {image_input}",
                "matched_brand": None,
                "similarity_score": 0.0,
                "all_matches": [],
            }
        try:
            target_img = Image.open(image_input).convert("RGB")
        except Exception as e:
            return {
                "flagged": False,
                "signals": [],
                "confidence": 0.0,
                "explanation": f"Failed to load image file: {str(e)}",
                "matched_brand": None,
                "similarity_score": 0.0,
                "all_matches": [],
            }
    elif isinstance(image_input, Image.Image):
        target_img = image_input.convert("RGB")
    else:
        return {
            "flagged": False,
            "signals": [],
            "confidence": 0.0,
            "explanation": "Invalid image input type. Expected file path or PIL Image.",
            "matched_brand": None,
            "similarity_score": 0.0,
            "all_matches": [],
        }

    # Compute perceptual and difference hashes for target
    if imagehash is not None:
        target_phash = imagehash.phash(target_img)
        target_dhash = imagehash.dhash(target_img)
    else:
        target_dhash = _calc_dhash(target_img)
        target_phash = target_dhash

    references = load_reference_hashes(template_dir)
    if not references:
        return {
            "flagged": False,
            "signals": [],
            "confidence": 0.0,
            "explanation": "No reference brand templates found in database.",
            "matched_brand": None,
            "similarity_score": 0.0,
            "all_matches": [],
        }

    matches = []
    best_brand = None
    best_score = 0.0

    for brand, ref_data in references.items():
        # Blended score: perceptual hash + difference hash
        p_sim = compute_visual_similarity(target_phash, ref_data["phash"])
        d_sim = compute_visual_similarity(target_dhash, ref_data["dhash"])
        combined_score = round(0.6 * p_sim + 0.4 * d_sim, 2)

        matches.append({
            "brand": brand,
            "similarity_score": combined_score,
            "phash_similarity": p_sim,
            "dhash_similarity": d_sim,
        })

        if combined_score > best_score:
            best_score = combined_score
            best_brand = brand

    matches = sorted(matches, key=lambda x: x["similarity_score"], reverse=True)

    is_flagged = best_score >= threshold
    signals = []
    explanation = ""

    if is_flagged:
        signals.append("VISUAL_LOGIN_SPOOF")
        confidence = min(99.0, max(75.0, best_score))
        explanation = (
            f"Page visual layout closely matches the reference login template for '{best_brand}' "
            f"with {best_score:.1f}% perceptual hash similarity (threshold: {threshold:.1f}%). "
            f"Indicates deceptive visual credential-harvesting page."
        )
    else:
        confidence = round(best_score * 0.4, 1)
        explanation = (
            f"No close visual match to reference login templates (closest template: "
            f"'{best_brand}' at {best_score:.1f}% similarity, below threshold {threshold:.1f}%)."
        )

    return {
        "flagged": is_flagged,
        "signals": signals,
        "confidence": round(confidence, 1),
        "explanation": explanation,
        "matched_brand": best_brand if is_flagged else None,
        "similarity_score": best_score,
        "all_matches": matches,
    }