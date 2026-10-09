"""Linux-only sealed, bounded copy of a host-approved read-only descriptor.

Never exposed as a UDX client path or generic IPC grant.  The source may be
modified during capture; double-read equality and stat checks REDUCE, but do
NOT eliminate, concurrent writer/torn-version risk.  The published *copy* is
immutable after a successful F_SEAL_WRITE/F_SEAL_GROW/F_SEAL_SHRINK/F_SEAL_SEAL.
Requires an authenticated, trusted host to select the descriptor. This class
is not a user-consent authority, platform sandbox, or atomic source snapshot.
"""
from __future__ import annotations
try:
    import fcntl
except ImportError:  # Windows/Android/iOS must not import POSIX-only symbols
    fcntl = None
import hashlib
import os
import sys
import threading
from .fd_reader import ApprovedFdReader, ReadGuardError, MAX_READ

_SEALS = ((fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
          fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL) if fcntl is not None else None)


class SealedSnapshot:
    def __init__(self, approved_fd: int, *, expected_uid: int, limit: int = MAX_READ):
        if sys.platform != 'linux' or fcntl is None or not hasattr(os, 'memfd_create'):
            raise ReadGuardError('UNSUPPORTED_PLATFORM')
        if type(expected_uid) is not int or expected_uid < 0:
            raise ReadGuardError('OWNER_REQUIRED')
        self._fd = None
        self._lock = threading.RLock()
        # Perform guarded reads twice and refuse if source changed between them.
        # os.pread() does not guarantee an atomic snapshot for in-place writers.
        with ApprovedFdReader(approved_fd, limit=limit, expected_uid=expected_uid) as reader:
            first = reader.read()
            second = reader.read()
        if first != second:
            raise ReadGuardError('SOURCE_UNSTABLE')
        memfd = os.memfd_create('udx-approved-snapshot', flags=os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            offset = 0
            while offset < len(first):
                written = os.write(memfd, first[offset:])
                if written <= 0:
                    raise ReadGuardError('SNAPSHOT_COPY_FAILED')
                offset += written
            fcntl.fcntl(memfd, fcntl.F_ADD_SEALS, _SEALS)
            if fcntl.fcntl(memfd, fcntl.F_GET_SEALS) & _SEALS != _SEALS:
                raise ReadGuardError('SNAPSHOT_UNSEALED')
            self._digest = hashlib.sha256(first).digest()
            self._size = len(first)
            self._fd = memfd
        except BaseException:
            os.close(memfd)
            raise

    def read(self) -> bytes:
        with self._lock:
            if self._fd is None:
                raise ReadGuardError('CLOSED')
            data = os.pread(self._fd, self._size + 1, 0)
            if len(data) != self._size or hashlib.sha256(data).digest() != self._digest:
                raise ReadGuardError('SNAPSHOT_INTEGRITY_FAILURE')
            return data

    def close(self):
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __enter__(self):
        with self._lock:
            if self._fd is None:
                raise ReadGuardError('CLOSED')
            return self

    def __exit__(self, *_):
        self.close()
