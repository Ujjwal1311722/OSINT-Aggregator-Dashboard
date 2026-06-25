"""
Metadata extraction for uploaded files.

Demonstrates data-leakage risk: images often embed GPS coordinates,
device info, and timestamps; documents embed author/software metadata
that can reveal internal usernames, software versions, and edit history;
archives reveal original folder structure and file timestamps; plain text
files can contain inadvertently-included emails, IPs, or other sensitive
strings worth flagging before sharing a file publicly.
"""

import os
import re
import zipfile
from datetime import datetime

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from pypdf import PdfReader

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _get_exif(image_path):
    image = Image.open(image_path)
    exif_data = image._getexif()
    if not exif_data:
        return {}

    exif = {}
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == "GPSInfo":
            gps_data = {}
            for gps_tag_id, gps_value in value.items():
                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                gps_data[gps_tag] = gps_value
            exif["GPSInfo"] = gps_data
        else:
            exif[tag] = str(value)
    return exif


def _gps_to_decimal(gps_info):
    """Convert EXIF GPS coordinates to decimal degrees, if present."""
    try:
        def to_deg(value):
            d, m, s = value
            return float(d) + float(m) / 60 + float(s) / 3600

        lat = to_deg(gps_info["GPSLatitude"])
        if gps_info.get("GPSLatitudeRef") == "S":
            lat = -lat

        lon = to_deg(gps_info["GPSLongitude"])
        if gps_info.get("GPSLongitudeRef") == "W":
            lon = -lon

        return {"latitude": lat, "longitude": lon}
    except (KeyError, ZeroDivisionError, TypeError):
        return None


def _extract_pdf_metadata(filepath):
    """
    Pull document-info metadata from a PDF: author, producer/creator software,
    creation/modification dates, and whether the file embeds JavaScript
    (a known malicious-PDF vector worth flagging in a security context).
    """
    reader = PdfReader(filepath)
    info = reader.metadata or {}

    def clean(value):
        return str(value) if value else None

    has_js = False
    try:
        root = reader.trailer["/Root"]
        has_js = "/Names" in root and "/JavaScript" in root["/Names"]
    except Exception:
        has_js = False

    return {
        "title": clean(info.title),
        "author": clean(info.author),
        "subject": clean(info.subject),
        "creator": clean(info.creator),
        "producer": clean(info.producer),
        "creation_date": clean(info.creation_date),
        "modification_date": clean(info.modification_date),
        "page_count": len(reader.pages),
        "has_embedded_javascript": has_js,
    }


def _extract_zip_metadata(filepath, max_entries=200):
    """
    Inspect a ZIP archive's internal file listing without extracting it.
    Archives often leak the original folder structure, usernames in file
    paths, and creation timestamps from whoever originally built the zip —
    none of which is visible from outside the archive.
    """
    with zipfile.ZipFile(filepath) as zf:
        infolist = zf.infolist()
        entries = []
        encrypted_count = 0

        for entry in infolist[:max_entries]:
            is_encrypted = bool(entry.flag_bits & 0x1)
            if is_encrypted:
                encrypted_count += 1
            entries.append({
                "name": entry.filename,
                "size": entry.file_size,
                "compressed_size": entry.compress_size,
                "modified": datetime(*entry.date_time).isoformat() if entry.date_time[0] >= 1980 else None,
                "is_dir": entry.is_dir(),
                "encrypted": is_encrypted,
            })

        return {
            "entry_count": len(infolist),
            "entries": entries,
            "truncated": len(infolist) > max_entries,
            "comment": zf.comment.decode("utf-8", errors="replace") if zf.comment else None,
            "any_encrypted": encrypted_count > 0,
            "encrypted_count": encrypted_count,
        }


def _extract_txt_metadata(filepath, max_bytes=2_000_000):
    """
    Basic text-file analysis: size/line/word counts, detected encoding,
    and a scan for emails/IPv4 addresses that may have been left in the
    file unintentionally before sharing it.
    """
    raw = open(filepath, "rb").read(max_bytes)

    encoding_used = "utf-8"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
        encoding_used = "latin-1 (fallback — file is not valid UTF-8)"

    lines = text.splitlines()
    words = text.split()

    emails_found = sorted(set(EMAIL_RE.findall(text)))[:25]
    ips_found = sorted(set(IPV4_RE.findall(text)))[:25]

    return {
        "size_bytes": os.path.getsize(filepath),
        "encoding_guess": encoding_used,
        "line_count": len(lines),
        "word_count": len(words),
        "char_count": len(text),
        "emails_found": emails_found,
        "ips_found": ips_found,
        "truncated": os.path.getsize(filepath) > max_bytes,
    }


def extract_metadata(filepath):
    """Extract metadata based on file type."""
    ext = os.path.splitext(filepath)[1].lower()

    if ext in (".jpg", ".jpeg", ".png"):
        try:
            exif = _get_exif(filepath)
            gps_decimal = None
            if "GPSInfo" in exif:
                gps_decimal = _gps_to_decimal(exif["GPSInfo"])

            return {
                "file_type": "image",
                "filename": os.path.basename(filepath),
                "exif": exif,
                "gps_coordinates": gps_decimal,
                "has_location_data": gps_decimal is not None,
            }
        except Exception as e:
            return {"file_type": "image", "error": f"EXIF extraction failed: {e}"}

    elif ext == ".pdf":
        try:
            pdf_meta = _extract_pdf_metadata(filepath)
            return {
                "file_type": "pdf",
                "filename": os.path.basename(filepath),
                "pdf_meta": pdf_meta,
            }
        except Exception as e:
            return {"file_type": "pdf", "error": f"PDF metadata extraction failed: {e}"}

    elif ext == ".zip":
        try:
            zip_meta = _extract_zip_metadata(filepath)
            return {
                "file_type": "zip",
                "filename": os.path.basename(filepath),
                "zip_meta": zip_meta,
            }
        except zipfile.BadZipFile:
            return {"file_type": "zip", "error": "Not a valid ZIP file (corrupted or wrong extension)."}
        except Exception as e:
            return {"file_type": "zip", "error": f"ZIP metadata extraction failed: {e}"}

    elif ext == ".txt":
        try:
            txt_meta = _extract_txt_metadata(filepath)
            return {
                "file_type": "txt",
                "filename": os.path.basename(filepath),
                "txt_meta": txt_meta,
            }
        except Exception as e:
            return {"file_type": "txt", "error": f"Text file analysis failed: {e}"}

    elif ext == ".docx":
        return {
            "file_type": "docx",
            "filename": os.path.basename(filepath),
            "note": "DOCX metadata extraction not yet implemented — use "
                    "python-docx's document.core_properties for author/company fields.",
        }

    return {"file_type": "unknown", "filename": os.path.basename(filepath)}
