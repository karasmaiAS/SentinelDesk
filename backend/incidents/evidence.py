import json
import mimetypes
import os
from pathlib import Path
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.utils.deconstruct import deconstructible


MAX_EVIDENCE_SIZE = 10 * 1024 * 1024
ALLOWED_EVIDENCE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".txt",
    ".log",
    ".csv",
    ".json",
}


@deconstructible
class PrivateEvidenceStorage(FileSystemStorage):
    def __init__(self):
        location = os.environ.get("SENTINELDESK_EVIDENCE_DIR")
        if not location:
            location = Path.home() / ".sentineldesk" / "private-evidence"
        super().__init__(location=str(location), base_url=None)

    def url(self, name):
        raise ValueError("Private evidence must be accessed through an authorized download view.")


def safe_original_filename(name):
    basename = name.replace("\\", "/").rsplit("/", 1)[-1]
    basename = "".join(
        character
        for character in basename
        if character.isalnum() or character in " ._-()"
    ).strip(" .")
    return basename[:255] or "evidence"


def evidence_upload_path(instance, filename):
    extension = Path(filename.replace("\\", "/")).suffix.lower()
    return f"{uuid4().hex}{extension}"


def evidence_content_type(filename):
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def validate_evidence_file(uploaded_file):
    name = safe_original_filename(getattr(uploaded_file, "name", ""))
    extension = Path(name).suffix.lower()
    if extension not in ALLOWED_EVIDENCE_EXTENSIONS:
        raise ValidationError(
            {"file": "Upload a PNG/JPEG image or a TXT, LOG, CSV, or JSON file."}
        )
    if uploaded_file.size > MAX_EVIDENCE_SIZE:
        raise ValidationError(
            {"file": f"Evidence files must be {MAX_EVIDENCE_SIZE // (1024 * 1024)} MB or smaller."}
        )

    start = uploaded_file.tell()
    sample = uploaded_file.read()
    uploaded_file.seek(start)
    if extension == ".png" and not sample.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValidationError({"file": "The uploaded file is not a valid PNG image."})
    if extension in {".jpg", ".jpeg"} and not sample.startswith(b"\xff\xd8\xff"):
        raise ValidationError({"file": "The uploaded file is not a valid JPEG image."})
    if extension in {".txt", ".log", ".csv", ".json"}:
        if b"\x00" in sample:
            raise ValidationError({"file": "Text evidence cannot contain binary data."})
        try:
            decoded = sample.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValidationError(
                {"file": "Text evidence must be UTF-8 encoded."}
            ) from error
        if extension == ".json":
            try:
                json.loads(decoded)
            except json.JSONDecodeError as error:
                raise ValidationError(
                    {"file": "The uploaded JSON evidence is not valid JSON."}
                ) from error
    return name, uploaded_file.size
