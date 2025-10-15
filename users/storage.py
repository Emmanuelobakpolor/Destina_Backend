from django.core.files.storage import FileSystemStorage
from .utils import get_image_url

class CloudinaryStorage(FileSystemStorage):
    """
    Custom storage backend that saves full Cloudinary URLs instead of relative paths.
    """

    def _save(self, name, content):
        # Call the parent _save to handle the file saving
        saved_name = super()._save(name, content)

        # Return the full Cloudinary URL instead of the relative path
        return get_image_url(saved_name)
