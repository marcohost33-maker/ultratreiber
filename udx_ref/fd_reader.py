"""POSIX handle-only read research adapter, never exposed over UDX IPC.

A *trusted host* must obtain the file descriptor through explicit user mediation
and own the OS identity / access checks. No caller-supplied path or filename.
No endorsement for untrusted same-UID clients. Not an atomic file snapshot.
"""
from __future__ import annotations
import os
import stat
import sys
try:
    import fcntl
except ImportError:
    fcntl = None

MAX_READ = 64 * 1024

class ReadGuardError(RuntimeError):
    pass

class ApprovedFdReader:
    def __init__(self, fd: int, *, limit: int = MAX_READ, expected_uid: int | None = None):
        if fcntl is None or os.name != 'posix' or not hasattr(os,'pread'):
            raise ReadGuardError('UNSUPPORTED_PLATFORM')
        if type(fd) is not int or fd < 0:
            raise ReadGuardError('INVALID_FD')
        if type(limit) is not int or not 1 <= limit <= MAX_READ:
            raise ReadGuardError('INVALID_LIMIT')
        self._fd = None
        try:
            info = os.fstat(fd)
            flags = fcntl.fcntl(fd,fcntl.F_GETFL)
            if not stat.S_ISREG(info.st_mode):
                raise ReadGuardError('NOT_REGULAR_FILE')
            if flags & os.O_ACCMODE != os.O_RDONLY:
                raise ReadGuardError('FD_NOT_READ_ONLY')
            if expected_uid is not None and (type(expected_uid) is not int or info.st_uid != expected_uid):
                raise ReadGuardError('OWNER_MISMATCH')
            if info.st_size < 0 or info.st_size > limit:
                raise ReadGuardError('SIZE_LIMIT')
            self._fd = os.dup(fd)
            self._identity = (info.st_dev,info.st_ino)
            self._stamp = (info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            self._limit = limit
        except OSError as exc:
            raise ReadGuardError('INVALID_FD') from exc

    def read(self) -> bytes:
        if self._fd is None:
            raise ReadGuardError('CLOSED')
        before=os.fstat(self._fd)
        if (before.st_dev,before.st_ino) != self._identity or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=self._stamp:
            raise ReadGuardError('RESOURCE_CHANGED')
        if before.st_size > self._limit:
            raise ReadGuardError('SIZE_LIMIT')
        data=os.pread(self._fd,self._limit+1,0)
        after=os.fstat(self._fd)
        if len(data) > self._limit:
            raise ReadGuardError('SIZE_LIMIT')
        if (after.st_dev,after.st_ino)!=self._identity or (after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=self._stamp:
            raise ReadGuardError('RESOURCE_CHANGED')
        if len(data) != before.st_size:
            raise ReadGuardError('RESOURCE_CHANGED')
        return data

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd=None

    def __enter__(self):
        if self._fd is None:raise ReadGuardError('CLOSED')
        return self

    def __exit__(self,*_):
        self.close()
