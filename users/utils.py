import hmac
import hashlib
import json
from django.conf import settings


def get_image_url(image_path):
    """
    Returns the full Cloudinary URL for a given image path.
    If the path is already a full Cloudinary URL, returns it as is.
    Otherwise, prepends the Cloudinary base URL.

    Args:
        image_path (str): The relative image path or full URL.

    Returns:
        str: The full Cloudinary URL or the original if already full.
    """
    if not image_path:
        return None

    cloudinary_base = "https://res.cloudinary.com/dwxs6zj5f/image/upload/"
    if image_path.startswith(cloudinary_base):
        return image_path
    else:
        return cloudinary_base + image_path


def verify_flutterwave_webhook_signature(payload, signature):
    """
    Verifies the Flutterwave webhook signature to ensure authenticity.

    Args:
        payload (str): The raw JSON payload from the webhook.
        signature (str): The signature from the 'verif-hash' header.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    secret = settings.FLUTTERWAVE_SECRET_KEY.encode('utf-8')
    expected_signature = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)
