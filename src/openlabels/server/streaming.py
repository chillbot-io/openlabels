"""
Memory-efficient streaming utilities for large data processing.

Provides:
- Streaming response generators for CSV, JSONL, and JSON formats
- Chunked batch processing for memory-efficient iteration
- Cursor-based pagination helper for large datasets

Usage:
    from openlabels.server.streaming import (
        stream_csv_response,
        stream_jsonl_response,
        stream_json_array_response,
        process_in_chunks,
        CursorPaginator,
    )
"""

import base64
import csv
import io
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime
from typing import Any, Generic, Optional, TypeVar
from uuid import UUID

from fastapi.responses import StreamingResponse
from sqlalchemy import Select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.logging import get_logger

logger = get_logger(__name__)


T = TypeVar("T")
R = TypeVar("R")


# =============================================================================
# STREAMING RESPONSE GENERATORS
# =============================================================================


async def stream_csv_response(
    data_iterator: AsyncIterator[dict],
    filename: str,
    fieldnames: list[str],
    chunk_size: int = 100,
) -> StreamingResponse:
    """
    Create streaming CSV response with constant memory usage.

    Yields CSV data in chunks to avoid loading entire dataset into memory.
    Each chunk is flushed immediately for true streaming behavior.

    Args:
        data_iterator: Async iterator yielding dictionaries with data
        fieldnames: List of CSV column names (keys from the dictionaries)
        filename: Filename for Content-Disposition header
        chunk_size: Number of rows to buffer before yielding (default: 100)

    Returns:
        FastAPI StreamingResponse with CSV content

    Example:
        async def get_results():
            async for result in db_iterator:
                yield {"id": result.id, "name": result.name}

        return await stream_csv_response(
            get_results(),
            filename="export.csv",
            fieldnames=["id", "name"],
        )
    """

    async def csv_generator() -> AsyncIterator[bytes]:
        """Generate CSV content in streaming chunks."""
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)

        # Write header
        writer.writeheader()
        header_content = buffer.getvalue()
        yield header_content.encode("utf-8")
        buffer.seek(0)
        buffer.truncate()

        row_count = 0
        chunk_count = 0

        try:
            async for row in data_iterator:
                writer.writerow(row)
                row_count += 1

                # Yield chunk when buffer reaches chunk_size
                if row_count % chunk_size == 0:
                    chunk_content = buffer.getvalue()
                    yield chunk_content.encode("utf-8")
                    buffer.seek(0)
                    buffer.truncate()
                    chunk_count += 1

            # Yield any remaining content
            remaining = buffer.getvalue()
            if remaining:
                yield remaining.encode("utf-8")
                chunk_count += 1

            logger.debug(
                "CSV streaming complete",
                total_rows=row_count,
                chunks_sent=chunk_count,
                filename=filename,
            )

        except Exception as e:
            logger.error(
                "Error during CSV streaming",
                error=str(e),
                rows_processed=row_count,
                filename=filename,
            )
            raise

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": "text/csv; charset=utf-8",
    }

    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers=headers,
    )


async def stream_jsonl_response(
    data_iterator: AsyncIterator[dict],
    filename: str,
) -> StreamingResponse:
    """
    Stream JSON Lines format - each line is an independent JSON object.

    JSON Lines (JSONL) is more streaming-friendly than JSON arrays because:
    - Each line can be parsed independently
    - No need to wait for complete response
    - Better for large datasets and real-time processing

    Args:
        data_iterator: Async iterator yielding dictionaries
        filename: Filename for Content-Disposition header

    Returns:
        FastAPI StreamingResponse with JSONL content

    Example:
        async def get_results():
            async for result in db_iterator:
                yield result.model_dump()

        return await stream_jsonl_response(
            get_results(),
            filename="export.jsonl",
        )
    """

    async def jsonl_generator() -> AsyncIterator[bytes]:
        """Generate JSONL content line by line."""
        row_count = 0

        try:
            async for item in data_iterator:
                # Serialize with custom encoder for datetime/UUID
                line = json.dumps(item, default=_json_serializer) + "\n"
                yield line.encode("utf-8")
                row_count += 1

            logger.debug(
                "JSONL streaming complete",
                total_rows=row_count,
                filename=filename,
            )

        except Exception as e:
            logger.error(
                "Error during JSONL streaming",
                error=str(e),
                rows_processed=row_count,
                filename=filename,
            )
            raise

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": "application/x-ndjson",
    }

    return StreamingResponse(
        jsonl_generator(),
        media_type="application/x-ndjson",
        headers=headers,
    )


async def stream_json_array_response(
    data_iterator: AsyncIterator[dict],
    filename: str,
) -> StreamingResponse:
    """
    Stream JSON array with proper comma handling.

    Streams a valid JSON array by handling opening/closing brackets
    and comma placement between items.

    Note: For very large datasets, prefer JSONL format as it allows
    line-by-line parsing without waiting for the complete response.

    Args:
        data_iterator: Async iterator yielding dictionaries
        filename: Filename for Content-Disposition header

    Returns:
        FastAPI StreamingResponse with JSON array content

    Example:
        async def get_results():
            async for result in db_iterator:
                yield result.model_dump()

        return await stream_json_array_response(
            get_results(),
            filename="export.json",
        )
    """

    async def json_array_generator() -> AsyncIterator[bytes]:
        """Generate JSON array content with proper formatting."""
        row_count = 0
        first_item = True

        try:
            # Opening bracket
            yield b"[\n"

            async for item in data_iterator:
                # Add comma before item (except first)
                if not first_item:
                    yield b",\n"
                first_item = False

                # Serialize item with indentation for readability
                serialized = json.dumps(item, default=_json_serializer, indent=2)
                # Indent each line by 2 spaces for nested array formatting
                indented = "  " + serialized.replace("\n", "\n  ")
                yield indented.encode("utf-8")
                row_count += 1

            # Closing bracket
            yield b"\n]"

            logger.debug(
                "JSON array streaming complete",
                total_rows=row_count,
                filename=filename,
            )

        except Exception as e:
            logger.error(
                "Error during JSON array streaming",
                error=str(e),
                rows_processed=row_count,
                filename=filename,
            )
            raise

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": "application/json; charset=utf-8",
    }

    return StreamingResponse(
        json_array_generator(),
        media_type="application/json",
        headers=headers,
    )


def _json_serializer(obj: Any) -> Any:
    """
    Custom JSON serializer for common non-serializable types.

    Handles:
    - datetime objects -> ISO format strings
    - UUID objects -> string representation
    - bytes -> base64 encoded string
    - Sets -> lists
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


# =============================================================================
# CHUNKED BATCH PROCESSING
# =============================================================================


async def process_in_chunks(
    items: AsyncIterator[T],
    processor: Callable[[list[T]], Awaitable[list[R]]],
    chunk_size: int = 100,
    on_progress: Optional[Callable[[int, int], Awaitable[None]]] = None,
) -> AsyncIterator[R]:
    """
    Process items in memory-efficient chunks.

    Collects items into chunks and processes them in batches, yielding
    results as they complete. This is useful for:
    - Batch database operations
    - Parallel API calls with rate limiting
    - Memory-constrained processing of large datasets

    Args:
        items: Async iterator of items to process
        processor: Async function that processes a list of items and returns results
        chunk_size: Number of items to collect before processing (default: 100)
        on_progress: Optional async callback (processed_count, chunk_number)
                    called after each chunk completes

    Yields:
        Processed results from each chunk

    Example:
        async def fetch_items():
            for i in range(10000):
                yield {"id": i, "url": f"https://api.example.com/item/{i}"}

        async def fetch_batch(items):
            # Batch API call
            results = await api_client.batch_fetch([i["url"] for i in items])
            return results

        async def report_progress(count, chunk):
            print(f"Processed {count} items (chunk {chunk})")

        async for result in process_in_chunks(
            fetch_items(),
            processor=fetch_batch,
            chunk_size=50,
            on_progress=report_progress,
        ):
            save_result(result)
    """
    chunk: list[T] = []
    processed_count = 0
    chunk_number = 0

    try:
        async for item in items:
            chunk.append(item)

            # Process when chunk is full
            if len(chunk) >= chunk_size:
                chunk_number += 1
                logger.debug(
                    "Processing chunk",
                    chunk_number=chunk_number,
                    chunk_size=len(chunk),
                )

                results = await processor(chunk)
                processed_count += len(chunk)

                # Call progress callback if provided
                if on_progress:
                    await on_progress(processed_count, chunk_number)

                # Yield results one by one
                for result in results:
                    yield result

                # Clear chunk for next batch
                chunk = []

        # Process remaining items
        if chunk:
            chunk_number += 1
            logger.debug(
                "Processing final chunk",
                chunk_number=chunk_number,
                chunk_size=len(chunk),
            )

            results = await processor(chunk)
            processed_count += len(chunk)

            if on_progress:
                await on_progress(processed_count, chunk_number)

            for result in results:
                yield result

        logger.info(
            "Chunked processing complete",
            total_processed=processed_count,
            total_chunks=chunk_number,
        )

    except Exception as e:
        logger.error(
            "Error during chunked processing",
            error=str(e),
            processed_count=processed_count,
            current_chunk=chunk_number,
        )
        raise


# =============================================================================
# CURSOR PAGINATION HELPER
# =============================================================================


class CursorPaginator(Generic[T]):
    """
    Efficient cursor-based pagination for large datasets.

    Benefits over offset-based pagination:
    - Constant time regardless of page (no slow OFFSET queries)
    - Stable pagination even with concurrent data changes
    - Better for infinite scroll UIs
    - No risk of skipping or duplicating items during pagination

    The cursor encodes the position in the result set as an opaque string,
    making pagination stateless and cacheable.

    Usage:
        from sqlalchemy import select
        from myapp.models import ScanResult

        # Create paginator
        base_query = select(ScanResult).where(ScanResult.tenant_id == tenant_id)
        paginator = CursorPaginator(
            session=db_session,
            base_query=base_query.order_by(ScanResult.created_at.desc()),
            cursor_columns=["created_at", "id"],
            page_size=50,
        )

        # Get first page
        page1 = await paginator.get_page()

        # Get next page using cursor
        page2 = await paginator.get_page(cursor=page1["next_cursor"])

        # Navigate backward
        prev_page = await paginator.get_page(
            cursor=page2["previous_cursor"],
            direction="backward"
        )
    """

    def __init__(
        self,
        session: AsyncSession,
        base_query: Select,
        cursor_columns: list[str],
        page_size: int = 50,
    ) -> None:
        """
        Initialize cursor paginator.

        Args:
            session: SQLAlchemy async session for database queries
            base_query: Base query with ordering applied (ORDER BY is required)
            cursor_columns: Column names to use for cursor encoding.
                          Should match ORDER BY columns for correct pagination.
                          First column is primary sort, additional columns are tiebreakers.
                          Example: ["created_at", "id"] for descending time order
            page_size: Number of items per page (default: 50)
        """
        self.session = session
        self.base_query = base_query
        self.cursor_columns = cursor_columns
        self.page_size = page_size

    async def get_page(
        self,
        cursor: Optional[str] = None,
        direction: str = "forward",
    ) -> dict[str, Any]:
        """
        Get a page of results.

        Args:
            cursor: Opaque cursor string from previous page (None for first page)
            direction: "forward" for next page, "backward" for previous page

        Returns:
            Dictionary containing:
            - items: List of result items
            - next_cursor: Cursor for next page (None if no more results)
            - previous_cursor: Cursor for previous page (None if at start)
            - has_next: Boolean indicating more results exist
            - has_previous: Boolean indicating previous results exist
            - page_size: Number of items per page

        Raises:
            ValueError: If cursor is invalid or malformed
        """
        query = self.base_query
        cursor_values: Optional[dict[str, Any]] = None

        # Decode cursor if provided
        if cursor:
            try:
                cursor_values = self._decode_cursor(cursor)
                logger.debug(
                    "Decoded pagination cursor",
                    cursor_columns=self.cursor_columns,
                    direction=direction,
                )
            except ValueError as e:
                logger.warning(
                    "Invalid pagination cursor provided",
                    error=str(e),
                )
                raise

        # Apply cursor filter
        if cursor_values:
            query = self._apply_cursor_filter(query, cursor_values, direction)

        # Fetch page_size + 1 to detect if there are more results
        query = query.limit(self.page_size + 1)

        result = await self.session.execute(query)
        items = list(result.scalars().all())

        # Check if there are more results
        has_next = len(items) > self.page_size
        if has_next:
            items = items[: self.page_size]

        # Build response
        next_cursor: Optional[str] = None
        previous_cursor: Optional[str] = None

        if items:
            # Generate next cursor from last item
            if has_next:
                next_cursor = self._encode_cursor(items[-1])

            # Generate previous cursor from first item if we used a cursor
            if cursor:
                previous_cursor = self._encode_cursor(items[0])

        return {
            "items": items,
            "next_cursor": next_cursor,
            "previous_cursor": previous_cursor,
            "has_next": has_next,
            "has_previous": cursor is not None,
            "page_size": self.page_size,
        }

    def _encode_cursor(self, item: T) -> str:
        """
        Encode item's cursor column values to an opaque cursor string.

        Args:
            item: Database model instance with cursor column attributes

        Returns:
            Base64 encoded cursor string
        """
        values: dict[str, Any] = {}

        for column in self.cursor_columns:
            value = getattr(item, column, None)

            # Convert to JSON-serializable types
            if isinstance(value, datetime):
                values[column] = value.isoformat()
            elif isinstance(value, UUID):
                values[column] = str(value)
            else:
                values[column] = value

        cursor_json = json.dumps(values, sort_keys=True)
        return base64.urlsafe_b64encode(cursor_json.encode()).decode()

    def _decode_cursor(self, cursor: str) -> dict[str, Any]:
        """
        Decode cursor string to column values.

        Args:
            cursor: Base64 encoded cursor string

        Returns:
            Dictionary of column names to values

        Raises:
            ValueError: If cursor is invalid
        """
        try:
            cursor_json = base64.urlsafe_b64decode(cursor.encode()).decode()
            values = json.loads(cursor_json)

            # Validate that cursor contains expected columns
            for column in self.cursor_columns:
                if column not in values:
                    raise ValueError(f"Cursor missing required column: {column}")

            return values

        except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as e:
            raise ValueError(f"Invalid cursor format: {e}")

    def _apply_cursor_filter(
        self,
        query: Select,
        cursor_values: dict[str, Any],
        direction: str,
    ) -> Select:
        """
        Apply cursor-based filter to query.

        For forward pagination with descending order:
            WHERE (col1, col2) < (val1, val2)

        For backward pagination:
            WHERE (col1, col2) > (val1, val2)

        Args:
            query: SQLAlchemy query to modify
            cursor_values: Decoded cursor values
            direction: "forward" or "backward"

        Returns:
            Query with cursor filter applied
        """
        from sqlalchemy import tuple_

        # Get column objects from the query's selected entity
        # We need to access the model class to get actual column objects
        try:
            # Extract the model class from the query
            entity = query.column_descriptions[0]["entity"]
            columns = [getattr(entity, col) for col in self.cursor_columns]
            values = tuple(cursor_values.get(col) for col in self.cursor_columns)

            if len(columns) == 1:
                # Single column cursor
                col = columns[0]
                val = values[0]
                if direction == "forward":
                    query = query.where(col < val)
                else:
                    query = query.where(col > val)
            else:
                # Multi-column cursor (tuple comparison)
                col_tuple = tuple_(*columns)
                if direction == "forward":
                    query = query.where(col_tuple < values)
                else:
                    query = query.where(col_tuple > values)

        except (AttributeError, IndexError, KeyError) as e:
            logger.error(
                "Failed to apply cursor filter",
                error=str(e),
                cursor_columns=self.cursor_columns,
            )
            raise ValueError(f"Failed to apply cursor filter: {e}")

        return query


# =============================================================================
# ASYNC ITERATOR UTILITIES
# =============================================================================


async def async_batched(
    iterator: AsyncIterator[T],
    batch_size: int,
) -> AsyncIterator[list[T]]:
    """
    Collect items from async iterator into batches.

    Useful for batching database inserts or API calls.

    Args:
        iterator: Async iterator to batch
        batch_size: Maximum items per batch

    Yields:
        Lists of items, each up to batch_size length

    Example:
        async for batch in async_batched(items, 100):
            await db.bulk_insert(batch)
    """
    batch: list[T] = []

    async for item in iterator:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []

    if batch:
        yield batch


async def async_enumerate(
    iterator: AsyncIterator[T],
    start: int = 0,
) -> AsyncIterator[tuple[int, T]]:
    """
    Async version of enumerate().

    Args:
        iterator: Async iterator to enumerate
        start: Starting index (default: 0)

    Yields:
        Tuples of (index, item)

    Example:
        async for i, item in async_enumerate(items):
            print(f"Processing item {i}: {item}")
    """
    index = start
    async for item in iterator:
        yield index, item
        index += 1


async def async_take(
    iterator: AsyncIterator[T],
    n: int,
) -> AsyncIterator[T]:
    """
    Take first n items from async iterator.

    Args:
        iterator: Async iterator to take from
        n: Maximum number of items to yield

    Yields:
        Up to n items from the iterator

    Example:
        # Get first 10 results
        async for item in async_take(all_results, 10):
            process(item)
    """
    count = 0
    async for item in iterator:
        if count >= n:
            break
        yield item
        count += 1
