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
