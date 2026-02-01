"""File processing mixin for ScrubIQ."""

from typing import Dict, List, Optional


class FileMixin:
    """
    File upload and processing operations.
    
    Requires these attributes on the class:
        _require_unlock: Callable
        _file_processor: Optional[FileProcessor]
        _models_loading: bool
    """

    def process_file(
        self,
        content: bytes,
        filename: str,
        content_type: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> dict:
        """
        Process a file synchronously.
        
        Args:
            content: File bytes
            filename: Original filename
            content_type: MIME type (inferred if not provided)
            conversation_id: Optional conversation to link to
            
        Returns:
            Job result dict with redacted_text, spans, etc.
        """
        self._require_unlock()
        
        if not self._file_processor:
            if self._models_loading:
                raise RuntimeError("MODELS_LOADING: File processing not ready yet.")
            raise RuntimeError("File processor not initialized")
        
        job = self._file_processor.process_file(
            content=content,
            filename=filename,
            content_type=content_type,
            conversation_id=conversation_id,
        )
        
        return job.to_result_dict() or job.to_dict()

    def process_file_async(
        self,
        content: bytes,
        filename: str,
        content_type: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> str:
        """
        Start async file processing. Returns job ID immediately.
        """
        self._require_unlock()
        
        if not self._file_processor:
            if self._models_loading:
                raise RuntimeError("MODELS_LOADING: File processing not ready yet.")
            raise RuntimeError("File processor not initialized")
        
        job = self._file_processor.process_file_async(
            content=content,
            filename=filename,
            content_type=content_type,
            conversation_id=conversation_id,
        )
        
        return job.id

    def get_upload_job(self, job_id: str) -> Optional[dict]:
        """Get upload job status."""
        self._require_unlock()
        
        if not self._file_processor:
            return None
        
        job = self._file_processor.get_job(job_id)
        return job.to_dict() if job else None

    def get_upload_result(self, job_id: str) -> Optional[dict]:
        """Get upload job result (only if complete)."""
        self._require_unlock()

        if not self._file_processor:
            return None

        return self._file_processor.get_job_result(job_id)

    def get_upload_results_batch(self, job_ids: List[str]) -> Dict[str, dict]:
        """
        Get multiple upload job results in a single operation (N+1 fix).

        Args:
            job_ids: List of job IDs to fetch

        Returns:
            Dict mapping job_id to result dict (only complete jobs included)
        """
        self._require_unlock()

        if not self._file_processor:
            return {}

        return self._file_processor.get_job_results_batch(job_ids)

    def get_redacted_image(self, job_id: str) -> Optional[tuple]:
        """
        Get redacted image for download.
        
        Returns:
            Tuple of (image_bytes, filename, content_type) or None
        """
        self._require_unlock()
        
        if not self._file_processor or not self._file_processor.image_store:
            return None
        
        from ..storage import ImageFileType
        
        image_store = self._file_processor.image_store
        
        for file_type in [ImageFileType.REDACTED, ImageFileType.REDACTED_PDF]:
            result = image_store.retrieve(job_id, file_type)
            if result:
                image_bytes, info = result
                return (image_bytes, info.original_filename, info.content_type)
        
        return None

    def list_upload_jobs(
        self,
        conversation_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        """List upload jobs."""
        self._require_unlock()
        
        if not self._file_processor:
            return []
        
        jobs = self._file_processor.list_jobs(
            conversation_id=conversation_id,
            limit=limit,
        )
        
        return [j.to_dict() for j in jobs]
