"""
UniGuard PCAP API (Milestone 11, Hardened in Milestone 15)

Handles PCAP and PCAPNG file uploads with path-traversal protection,
file size enforcement, and safe internal storage isolation.
"""
import os
import uuid
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException

from backend.app.config import settings
from backend.app.schemas.pcap import PcapJobStatusResponse, PcapJobUploadResponse
from backend.app.services.pcap_service import pcap_service

logger = logging.getLogger("uniguard.pcap")
router = APIRouter(prefix="/pcap", tags=["PCAP Ingestion"])


@router.post("/upload", response_model=PcapJobUploadResponse)
async def upload_pcap(file: UploadFile = File(...)):
    """
    Upload a .pcap or .pcapng file for offline analysis.
    The file is stored securely using an internal UUID filename within the
    configured upload directory, preventing path traversal and public exposure.
    It is automatically deleted when background processing completes.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing.")
        
    # Sanitize original filename (prevent path traversal, null bytes, backslashes)
    raw_name = file.filename.replace("\x00", "").replace("\\", "/")
    sanitized_name = os.path.basename(raw_name)
    if not sanitized_name or sanitized_name in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename.")

    ext = os.path.splitext(sanitized_name)[1].lower()
    if ext not in [".pcap", ".pcapng"]:
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported.")
        
    # Create safe internal path within configured upload directory
    upload_dir = os.path.abspath(settings.pcap_upload_dir)
    os.makedirs(upload_dir, exist_ok=True)
    
    safe_filename = f"upload_{uuid.uuid4().hex}{ext}"
    file_path = os.path.abspath(os.path.join(upload_dir, safe_filename))
    
    # Path traversal validation: ensure destination is within upload_dir
    if not file_path.startswith(upload_dir):
        logger.warning("Path traversal attempt detected in upload: %s", raw_name)
        raise HTTPException(status_code=400, detail="Path traversal attempt detected.")
    
    # Enforce size constraints and stream safely to disk
    max_bytes = settings.pcap_max_file_size_mb * 1024 * 1024
    bytes_read = 0
    
    try:
        with open(file_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                bytes_read += len(chunk)
                if bytes_read > max_bytes:
                    raise HTTPException(
                        status_code=413, 
                        detail=f"File exceeds maximum allowed size of {settings.pcap_max_file_size_mb} MB."
                    )
                buffer.write(chunk)
    except HTTPException:
        # Cleanup partial file on size limit or validation error
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
        raise
    except Exception as e:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
        logger.error("Failed to save PCAP upload: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")

    logger.info("PCAP upload received: %s -> %s (%d bytes)", sanitized_name, safe_filename, bytes_read)

    # Kick off background job using sanitized filename
    return pcap_service.start_job(file_path, sanitized_name)


@router.get("/status/{job_id}", response_model=PcapJobStatusResponse)
def get_pcap_status(job_id: str):
    """Retrieve the status of a background PCAP processing job."""
    job = pcap_service.get_job_status(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job
