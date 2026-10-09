"""W10 internal-only, fail-closed durable one-use FD handoff admission.

NOT a user-consent authority and NOT exposed on public UDX IPC.
A caller MUST be an authenticated, trusted host, after real OS consent.
SQLite WAL+FULL is local resilience, NOT a tamper-proof ledger.
"""
from __future__ import annotations
import os
import secrets
import sqlite3
import stat
import time
import threading
from contextlib import contextmanager
from pathlib import Path
from .fd_reader import MAX_READ, ApprovedFdReader

class GrantDenied(RuntimeError):
    pass

_STATES = frozenset(('ISSUED','INFLIGHT','COMPLETED','REVOKED','REVOKED_INFLIGHT','QUARANTINED','EXPIRED'))


def _secure_store(path: str):
    # W12: the owner/mode checks below are POSIX semantics. On Windows os.getuid is
    # absent and st_mode does not express a DACL, so deny with a typed reason instead
    # of an AttributeError (or a vacuous check on an emulated mode).
    if os.name != 'posix' or not hasattr(os, 'getuid'):
        raise GrantDenied('UNSUPPORTED_PLATFORM')
    p = Path(path)
    if not p.is_absolute() or p.name in ('', '.', '..'):
        raise GrantDenied('ABSOLUTE_STORE_PATH_REQUIRED')
    parent = p.parent
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or (info.st_mode & 0o077):
        raise GrantDenied('UNSAFE_STORE_DIRECTORY')
    try:
        fd = os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0),0o600)
        os.close(fd)
    except FileExistsError:
        pass
    info = os.lstat(p)
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
        info.st_uid != os.getuid() or (info.st_mode & 0o077) or info.st_nlink != 1):
        raise GrantDenied('UNSAFE_STORE_FILE')
    return str(p)


def _fd_properties(fd: int, owner_uid: int):
    if type(owner_uid) is not int or owner_uid < 0:
        raise GrantDenied('BAD_OWNER')
    try:
        with ApprovedFdReader(fd, expected_uid=owner_uid) as reader:
            # Reverify observable source stability at admission, not atomic snapshot proof.
            reader.read()
            info = os.fstat(fd)
            return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    except (OSError, RuntimeError) as e:
        raise GrantDenied('INVALID_SOURCE_HANDLE') from e


class DurableGrantStore:
    def __init__(self, db_path: str, *, clock_ns=None):
        self._tx_lock=threading.RLock()
        self.path = _secure_store(db_path)
        self._now = clock_ns if clock_ns is not None else time.time_ns
        self.db = sqlite3.connect(self.path,timeout=3, isolation_level=None,check_same_thread=False)
        self.db.execute('PRAGMA busy_timeout=3000')
        if self.db.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() != 'wal':
            raise GrantDenied('WAL_REQUIRED')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA foreign_keys=ON')
        if self.db.execute('PRAGMA synchronous').fetchone()[0] != 2:
            raise GrantDenied('FULL_SYNC_REQUIRED')
        self.db.execute('''CREATE TABLE IF NOT EXISTS grants (
          grant_id TEXT PRIMARY KEY, issuer_uid INTEGER NOT NULL, recipient_uid INTEGER NOT NULL,
          dev INTEGER NOT NULL, ino INTEGER NOT NULL, size INTEGER NOT NULL,
          mtime_ns INTEGER NOT NULL, ctime_ns INTEGER NOT NULL,
          expires_ns INTEGER NOT NULL, state TEXT NOT NULL,
          request_id TEXT UNIQUE, CHECK(state IN ('ISSUED','INFLIGHT','COMPLETED','REVOKED','REVOKED_INFLIGHT','QUARANTINED','EXPIRED'))
        )''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS clock_guard (id INTEGER PRIMARY KEY CHECK(id=1), high_ns INTEGER NOT NULL)''')
    @contextmanager
    def _tx(self):
        # One sqlite connection is shared across threads: never interleave txns.
        with self._tx_lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
    def _clock(self):
        now = self._now()
        if type(now) is not int or now <= 0:
            raise GrantDenied('INVALID_CLOCK')
        last = self.db.execute('SELECT high_ns FROM clock_guard WHERE id=1').fetchone()
        if last is not None and now < last[0]:
            raise GrantDenied('CLOCK_ROLLBACK')
        self.db.execute('INSERT INTO clock_guard(id,high_ns) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET high_ns=excluded.high_ns',(now,))
        return now
    def issue(self, fd: int, *, issuer_uid: int, recipient_uid: int, ttl_seconds: int=60):
        if type(issuer_uid) is not int or type(recipient_uid) is not int or min(issuer_uid,recipient_uid)<0:
            raise GrantDenied('BAD_PRINCIPAL')
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise GrantDenied('BAD_TTL')
        props = _fd_properties(fd,issuer_uid)
        gid = secrets.token_hex(20)
        with self._tx():
            now = self._clock()
            self.db.execute('INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?,?,NULL)',
                            (gid,issuer_uid,recipient_uid,*props,now+ttl_seconds*10**9,'ISSUED'))
        return gid
    def claim(self, grant_id: str, fd: int, *, issuer_uid: int, recipient_uid: int, request_id: str):
        import uuid
        if type(grant_id) is not str or len(grant_id)!=40 or any(ch not in '0123456789abcdef' for ch in grant_id):
            raise GrantDenied('BAD_GRANT_ID')
        try:
            if type(request_id) is not str or str(uuid.UUID(request_id)) != request_id:
                raise ValueError
        except (ValueError,AttributeError):
            raise GrantDenied('BAD_REQUEST_ID') from None
        props = _fd_properties(fd,issuer_uid)
        expired = False
        with self._tx():
            now = self._clock()
            row = self.db.execute('SELECT issuer_uid, recipient_uid,dev,ino,size,mtime_ns,ctime_ns,expires_ns,state FROM grants WHERE grant_id=?',(grant_id,)).fetchone()
            if row is None:raise GrantDenied('UNKNOWN_GRANT')
            if now >= row[7]:
                if row[8]=='ISSUED':self.db.execute('UPDATE grants SET state=? WHERE grant_id=?',('EXPIRED',grant_id))
                expired = True
            elif row[8]!='ISSUED':raise GrantDenied('NOT_ISSUED')
            elif row[:2]!=(issuer_uid,recipient_uid) or row[2:7]!=props:
                raise GrantDenied('SCOPE_MISMATCH')
            else:
                try:
                    self.db.execute('UPDATE grants SET state=?,request_id=? WHERE grant_id=?',('INFLIGHT',request_id,grant_id))
                except sqlite3.IntegrityError as e:
                    raise GrantDenied('REQUEST_REPLAY') from e
        if expired:raise GrantDenied('EXPIRED')
    def finish(self, grant_id: str, request_id: str):
        with self._tx():
            now=self._clock()
            row=self.db.execute('SELECT state,request_id,expires_ns FROM grants WHERE grant_id=?',(grant_id,)).fetchone()
            if row is None or row[1]!=request_id or row[0]!='INFLIGHT' or now>=row[2]:
                # We cannot safely assert success; caller should quarantine.
                raise GrantDenied('UNCERTAIN_OR_REVOKED')
            self.db.execute('UPDATE grants SET state=? WHERE grant_id=?',('COMPLETED',grant_id))
    def revoke(self, grant_id: str):
        with self._tx():
            self._clock()
            row=self.db.execute('SELECT state FROM grants WHERE grant_id=?',(grant_id,)).fetchone()
            if row is None:raise GrantDenied('UNKNOWN_GRANT')
            if row[0]=='ISSUED': self.db.execute('UPDATE grants SET state=? WHERE grant_id=?',('REVOKED',grant_id))
            elif row[0]=='INFLIGHT':self.db.execute('UPDATE grants SET state=? WHERE grant_id=?',('REVOKED_INFLIGHT',grant_id))
            else:raise GrantDenied('NOT_REVOCABLE')
    def quarantine(self, grant_id: str):
        with self._tx():
            self._clock()
            self.db.execute("UPDATE grants SET state='QUARANTINED' WHERE grant_id=? AND state IN ('INFLIGHT','REVOKED_INFLIGHT')",(grant_id,))
    def recover_inflight(self):
        """Explicit supervisor-start operation. NEVER silently redispatch."""
        with self._tx():
            self._clock()
            count=self.db.execute("SELECT count(*) FROM grants WHERE state IN ('INFLIGHT','REVOKED_INFLIGHT')").fetchone()[0]
            self.db.execute("UPDATE grants SET state='QUARANTINED' WHERE state IN ('INFLIGHT','REVOKED_INFLIGHT')")
            return count
    def state(self, grant_id: str):
        with self._tx_lock:
            row=self.db.execute('SELECT state FROM grants WHERE grant_id=?',(grant_id,)).fetchone()
            return row[0] if row else None
    def close(self):
        with self._tx_lock:
            self.db.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
