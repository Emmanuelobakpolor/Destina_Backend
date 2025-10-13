from django.core.files.storage import Storage
from django.core.files.base import File
from supabase import create_client, Client
from django.conf import settings
import os
from io import BytesIO

class SupabaseStorage(Storage):
    def __init__(self):
        self.supabase: Client = create_client(
            supabase_url=settings.SUPABASE_URL,
            supabase_key=settings.SUPABASE_SERVICE_ROLE_KEY
        )
        self.bucket_name = settings.SUPABASE_BUCKET_NAME

    def _save(self, name, content):
        """Save file to Supabase storage"""
        try:
            # Read content into bytes
            if hasattr(content, 'read'):
                content_bytes = content.read()
                if hasattr(content, 'seek'):
                    content.seek(0)
            else:
                content_bytes = content

            # Upload to Supabase
            response = self.supabase.storage.from_(self.bucket_name).upload(
                path=name,
                file=content_bytes,
                file_options={"content-type": getattr(content, 'content_type', 'application/octet-stream')}
            )

            return name
        except Exception as e:
            print(f"Supabase upload error: {e}")
            raise

    def _open(self, name, mode='rb'):
        """Open file from Supabase storage"""
        try:
            response = self.supabase.storage.from_(self.bucket_name).download(name)
            return File(BytesIO(response), name)
        except Exception as e:
            print(f"Supabase download error: {e}")
            raise

    def exists(self, name):
        """Check if file exists in Supabase storage"""
        try:
            # Try to get file info
            self.supabase.storage.from_(self.bucket_name).list(path=os.path.dirname(name) or '')
            return True
        except:
            return False

    def delete(self, name):
        """Delete file from Supabase storage"""
        try:
            self.supabase.storage.from_(self.bucket_name).remove([name])
        except Exception as e:
            print(f"Supabase delete error: {e}")

    def url(self, name):
        """Get public URL for file"""
        return f"{settings.SUPABASE_URL}/storage/v1/object/public/{self.bucket_name}/{name}"

    def size(self, name):
        """Get file size"""
        try:
            # This is a simplified implementation
            # In a real scenario, you'd get metadata from Supabase
            return 0  # Placeholder
        except:
            return 0

    def accessed_time(self, name):
        """Get last accessed time"""
        return None

    def created_time(self, name):
        """Get creation time"""
        return None

    def modified_time(self, name):
        """Get last modified time"""
        return None
