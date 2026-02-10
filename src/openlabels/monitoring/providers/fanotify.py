"""
Fanotify provider for real-time Linux filesystem monitoring (Phase I).

Uses the ``fanotify`` kernel API via ``ctypes`` to monitor file access
and modification events with minimal overhead.  Operates in **per-path**
mode (``FAN_MARK_ADD``), driven by the monitoring registry.

Dual-mode operation:
* **Batch** — ``collect(since)`` for backward-compatible harvester use.
* **Stream** — ``stream(shutdown_event)`` for ``EventStreamManager``.

Only available on Linux with ``CAP_SYS_ADMIN``.  On other platforms
``is_available()`` returns ``False``.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import logging
import os
import struct
import sys
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path

from openlabels.monitoring.providers.base import RawAccessEvent

logger = logging.getLogger(__name__)

# ── Platform detection ───────────────────────────────────────────────

_IS_LINUX = sys.platform == "linux"

# ── fanotify constants ───────────────────────────────────────────────

# fanotify_init flags
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_CLASS_PRE_CONTENT = 0x00000008
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_REPORT_FID = 0x00000200

# fanotify_mark flags
FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_FILESYSTEM = 0x00000100

# Event mask flags
FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_DELETE_SELF = 0x00000400
FAN_MOVE_SELF = 0x00000800
FAN_ONDIR = 0x40000000
FAN_EVENT_ON_CHILD = 0x08000000

# Default mask: file modifications, creates, deletes, renames
DEFAULT_EVENT_MASK = (
    FAN_MODIFY
    | FAN_CLOSE_WRITE
    | FAN_CREATE
    | FAN_DELETE
    | FAN_MOVED_FROM
    | FAN_MOVED_TO
)

# sizeof(struct fanotify_event_metadata) on 64-bit Linux
# Layout: uint32_t event_len, uint8_t vers, uint8_t reserved,
#         uint16_t metadata_len, uint64_t mask (aligned), int32_t fd, int32_t pid
_FANOTIFY_EVENT_SIZE = 24

# Syscall numbers (x86_64)
_SYS_FANOTIFY_INIT = 300
_SYS_FANOTIFY_MARK = 301


def _mask_to_action(mask: int) -> str:
    """Map a fanotify event mask to an AccessAction string."""
    if mask & (FAN_DELETE | FAN_DELETE_SELF):
        return "delete"
    if mask & (FAN_MOVED_FROM | FAN_MOVED_TO | FAN_MOVE_SELF):
        return "rename"
    if mask & (FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CREATE):
        return "write"
    if mask & FAN_ACCESS:
        return "read"
    return "write"


# ── /proc helpers ────────────────────────────────────────────────────

def _resolve_pid_user(pid: int) -> str | None:
    """Resolve PID to username via /proc/{pid}/status."""
    try:
        status_path = Path(f"/proc/{pid}/status")
        if not status_path.exists():
            return None
        text = status_path.read_text()
        for line in text.splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
                try:
                    import pwd
                    return pwd.getpwuid(uid).pw_name
                except (KeyError, ImportError):
                    return str(uid)
    except (OSError, ValueError):
        pass
    return None


def _resolve_fd_path(fd: int) -> str | None:
    """Resolve an open file descriptor to its path via /proc/self/fd."""
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None


# ── libc wrappers ────────────────────────────────────────────────────

_libc_cache = None


def _get_libc():
    """Load and cache libc for syscall access."""
    global _libc_cache
    if _libc_cache is not None:
        return _libc_cache
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        libc_name = "libc.so.6"
    _libc_cache = ctypes.CDLL(libc_name, use_errno=True)
    return _libc_cache


def _fanotify_init(flags: int = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK) -> int:
    """Call fanotify_init(). Returns fd or -1 on error."""
    if not _IS_LINUX:
        return -1
    try:
        libc = _get_libc()
        fd = libc.syscall(_SYS_FANOTIFY_INIT, flags, os.O_RDONLY)
        if fd < 0:
            errno = ctypes.get_errno()
            logger.warning("fanotify_init failed: errno=%d", errno)
        return fd
    except Exception:
        logger.warning("fanotify_init failed", exc_info=True)
        return -1


def _fanotify_mark(
    fan_fd: int,
    flags: int,
    mask: int,
    dirfd: int,
    path: str | None,
) -> bool:
    """Call fanotify_mark(). Returns True on success."""
    if not _IS_LINUX:
        return False
    try:
        libc = _get_libc()
        path_bytes = path.encode("utf-8") if path else None

        # fanotify_mark(fan_fd, flags, mask, dirfd, pathname)
        # mask is uint64_t — need to pass as two args on some platforms
        result = libc.syscall(
            _SYS_FANOTIFY_MARK,
            fan_fd,
            flags,
            mask,
            dirfd,
            path_bytes,
        )
        if result < 0:
            errno = ctypes.get_errno()
            logger.warning(
                "fanotify_mark failed for %s: errno=%d", path, errno,
            )
            return False
        return True
    except Exception:
        logger.warning("fanotify_mark failed for %s", path, exc_info=True)
        return False


# ── FanotifyProvider ─────────────────────────────────────────────────


class FanotifyProvider:
    """Real-time Linux filesystem event provider via fanotify.

    Implements the ``EventProvider`` protocol for harvester compatibility
    and provides an async ``stream()`` method for ``EventStreamManager``.

    Uses per-path monitoring (``FAN_MARK_ADD``) driven by the monitoring
    registry.  Call ``update_watched_paths()`` to add/remove paths.
    """

    def __init__(
        self,
        watched_paths: list[str] | None = None,
        event_mask: int = DEFAULT_EVENT_MASK,
    ) -> None:
        self._event_mask = event_mask
        self._fan_fd: int = -1
        self._marked_paths: set[str] = set()

        # Initialize fanotify fd
        if _IS_LINUX:
            self._fan_fd = _fanotify_init()
            if self._fan_fd >= 0 and watched_paths:
                for p in watched_paths:
                    self._mark_path(p)

    @property
    def name(self) -> str:
        return "fanotify"

    @staticmethod
    def is_available() -> bool:
        """Return True if running on Linux with fanotify support.

        Performs a quick probe: calls ``fanotify_init()`` and immediately
        closes the fd.  Returns ``False`` on non-Linux or if the process
        lacks ``CAP_SYS_ADMIN``.
        """
        if not _IS_LINUX:
            return False
        fd = _fanotify_init()
        if fd < 0:
            return False
        try:
            os.close(fd)
        except OSError:
            pass
        return True

    def _mark_path(self, path: str) -> bool:
        """Add fanotify mark for a file or directory."""
        if self._fan_fd < 0:
            return False
        if path in self._marked_paths:
            return True

        success = _fanotify_mark(
            self._fan_fd,
            FAN_MARK_ADD,
            self._event_mask,
            -1,  # AT_FDCWD
            path,
        )
        if success:
            self._marked_paths.add(path)
            logger.debug("fanotify mark added: %s", path)
        return success

    def _unmark_path(self, path: str) -> bool:
        """Remove fanotify mark for a file or directory."""
        if self._fan_fd < 0:
            return False
        if path not in self._marked_paths:
            return True

        success = _fanotify_mark(
            self._fan_fd,
            FAN_MARK_REMOVE,
            self._event_mask,
            -1,
            path,
        )
        if success:
            self._marked_paths.discard(path)
            logger.debug("fanotify mark removed: %s", path)
        return success

    def update_watched_paths(self, paths: list[str]) -> None:
        """Sync fanotify marks to match the given path list."""
        new_set = set(paths)
        to_add = new_set - self._marked_paths
        to_remove = self._marked_paths - new_set

        for p in to_remove:
            self._unmark_path(p)
        for p in to_add:
            self._mark_path(p)

    def _read_events_sync(self) -> list[RawAccessEvent]:
        """Read available events from the fanotify fd (non-blocking)."""
        if self._fan_fd < 0:
            return []

        events: list[RawAccessEvent] = []
        buf_size = 4096

        try:
            data = os.read(self._fan_fd, buf_size)
        except BlockingIOError:
            return []
        except OSError as e:
            logger.warning("fanotify read failed: %s", e)
            return []

        offset = 0
        now = datetime.now(timezone.utc)

        while offset + _FANOTIFY_EVENT_SIZE <= len(data):
            # Parse fanotify_event_metadata (24 bytes)
            # struct layout: uint32_t event_len, uint8_t vers, uint8_t reserved,
            #                uint16_t metadata_len, uint64_t mask,
            #                int32_t fd, int32_t pid
            event_len = struct.unpack_from("<I", data, offset)[0]
            if event_len < _FANOTIFY_EVENT_SIZE or offset + event_len > len(data):
                break

            mask = struct.unpack_from("<Q", data, offset + 8)[0]
            fd = struct.unpack_from("<i", data, offset + 16)[0]
            pid = struct.unpack_from("<i", data, offset + 20)[0]

            # Resolve file path from fd
            file_path = None
            if fd >= 0:
                file_path = _resolve_fd_path(fd)
                # Close the event fd to prevent fd leak
                try:
                    os.close(fd)
                except OSError:
                    pass

            if file_path:
                user_name = _resolve_pid_user(pid) if pid > 0 else None

                events.append(RawAccessEvent(
                    file_path=file_path,
                    event_time=now,
                    action=_mask_to_action(mask),
                    event_source="fanotify",
                    user_name=user_name,
                    process_id=pid if pid > 0 else None,
                    raw={"mask": mask, "pid": pid},
                ))

            offset += event_len

        return events

    # ── EventProvider protocol ───────────────────────────────────────

    async def collect(
        self, since: datetime | None = None,
    ) -> list[RawAccessEvent]:
        """Batch-collect events (harvester-compatible)."""
        loop = asyncio.get_running_loop()
        events = await loop.run_in_executor(None, self._read_events_sync)

        if since:
            events = [e for e in events if e.event_time > since]

        return events

    # ── Streaming mode (for EventStreamManager) ──────────────────────

    async def stream(
        self,
        shutdown_event: asyncio.Event,
        poll_interval: float = 0.25,
    ) -> AsyncIterator[list[RawAccessEvent]]:
        """Yield batches of events as they arrive.

        Reads the fanotify fd every *poll_interval* seconds until
        *shutdown_event* is set.
        """
        loop = asyncio.get_running_loop()
        while not shutdown_event.is_set():
            try:
                events = await loop.run_in_executor(
                    None, self._read_events_sync,
                )
                if events:
                    yield events
            except Exception:
                logger.warning("fanotify stream read failed", exc_info=True)

            try:
                await asyncio.wait_for(
                    shutdown_event.wait(), timeout=poll_interval,
                )
                break
            except asyncio.TimeoutError:
                pass

    # ── Cleanup ──────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the fanotify file descriptor."""
        if self._fan_fd >= 0:
            try:
                os.close(self._fan_fd)
            except OSError:
                pass
            self._fan_fd = -1
            logger.info("fanotify provider closed")
        self._marked_paths.clear()

    def __del__(self) -> None:
        self.close()
