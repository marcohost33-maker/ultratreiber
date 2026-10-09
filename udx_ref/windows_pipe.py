"""W12 Windows named-pipe peer-SID probe -- Python/ctypes runtime port of
``windows/udx_sid_probe.cpp`` (W4 C++ candidate, still uncompiled).

RESEARCH ONLY. NOT a UDX broker, no OS action, no request/response protocol.
The only positive observable is the fixed 7-byte handshake ``PEER_OK``.

What is reproduced 1:1 from the C++ candidate (see docs/W12_WINDOWS_LANE.md):
  * protected DACL ``D:P(A;;GA;;;SY)(A;;GA;;;<current user SID>)`` built via
    ConvertStringSecurityDescriptorToSecurityDescriptorW
  * CreateNamedPipeW with FILE_FLAG_FIRST_PIPE_INSTANCE and
    PIPE_REJECT_REMOTE_CLIENTS, one instance, 4096/4096 buffers, byte mode
  * read exactly one byte BEFORE ImpersonateNamedPipeClient
  * OpenThreadToken(TOKEN_QUERY, OpenAsSelf=TRUE), TokenUser (<=65536 bytes),
    IsValidSid, EqualSid against the server SID
  * RevertToSelf failure terminates the process (exit code 30)

Deliberate differences (hardening, each with its own negative test):
  * absolute deadline over connect+read+write+drain via overlapped I/O and
    CancelIoEx (C++: blocking calls, no deadline)
  * explicit TokenImpersonationLevel >= SecurityImpersonation check. The C++
    candidate does not check the level; an Identification-level token still
    answers TokenUser, so the C++ server would accept such a client.
  * GetNamedPipeClientProcessId is recorded; its failure denies
  * refuse to run on a thread that is already impersonating (RevertToSelf would
    otherwise drop that outer identity)
  * no FlushFileBuffers (unbounded); instead a deadline-bounded wait for the
    client to close, reported as ``response_drained``
  * every Win32 failure is a typed denial; no positive result on any error path
"""
from __future__ import annotations

import contextlib
import ctypes
import json
import math
import os
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass

# --- constants (winbase.h / winnt.h / winerror.h) --------------------------
PIPE_PREFIX = '\\\\.\\pipe\\'
DEFAULT_PIPE_NAME = PIPE_PREFIX + 'UDX_W4_SID_PROBE'   # same name as the C++ probe
RESPONSE = b'PEER_OK'
MAX_DEADLINE_S = 300.0
TOKEN_INFO_MAX = 65536                                 # C++ query_sid cap
REVERT_FAILURE_EXIT = 30                               # C++ TerminateProcess code

PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
FILE_FLAG_OVERLAPPED = 0x40000000
PIPE_TYPE_BYTE = 0x0
PIPE_READMODE_BYTE = 0x0
PIPE_WAIT = 0x0
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_ANONYMOUS = 0 << 16
SECURITY_IDENTIFICATION = 1 << 16
SECURITY_IMPERSONATION = 2 << 16
SECURITY_DELEGATION = 3 << 16
SECURITY_EFFECTIVE_ONLY = 0x00080000
SECURITY_CONTEXT_TRACKING = 0x00040000
# W13 (Aegis P1-a): the client NEVER grants Impersonation. Static tracking
# (no SECURITY_CONTEXT_TRACKING), effective privileges only. 'anonymous' exists
# solely as a negative-test surface.
CLIENT_SQOS_LEVELS = {
    'identification': SECURITY_IDENTIFICATION,
    'anonymous': SECURITY_ANONYMOUS,
}
SQOS_LEVELS = CLIENT_SQOS_LEVELS            # backwards-compatible name
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# SECURITY_IMPERSONATION_LEVEL
SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation = 0, 1, 2, 3

TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_ADJUST_DEFAULT = 0x0080
TokenUser = 1
TokenImpersonationLevel = 9
TokenSessionId = 12
TokenIntegrityLevel = 25
TokenIsAppContainer = 29
TokenIsRestricted = 40
TokenImpersonation = 2
SE_GROUP_INTEGRITY = 0x00000020
SECURITY_MANDATORY_MEDIUM_RID = 0x2000

SE_KERNEL_OBJECT = 6
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
LABEL_SECURITY_INFORMATION = 0x00000010
SE_DACL_PROTECTED = 0x1000
SDDL_REVISION_1 = 1
ACCESS_ALLOWED_ACE_TYPE = 0

ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_BROKEN_PIPE = 109
ERROR_PIPE_BUSY = 231
ERROR_NO_DATA = 232
ERROR_MORE_DATA = 234
ERROR_PIPE_CONNECTED = 535
ERROR_OPERATION_ABORTED = 995
ERROR_IO_PENDING = 997
ERROR_NO_TOKEN = 1008
ERROR_CANT_OPEN_ANONYMOUS = 1347
ERROR_CANNOT_IMPERSONATE = 1368

WAIT_OBJECT_0 = 0x0
WAIT_TIMEOUT = 0x102
INFINITE = 0xFFFFFFFF

_SID_TEXT = re.compile(r'S-1-[0-9]{1,13}(-[0-9]{1,10}){1,15}')


class UnsupportedPlatform(RuntimeError):
    pass


class PipeSetupError(OSError):
    """Pipe could not be created; carries the Win32 error code."""


def build_sddl(sid_text: str) -> str:
    """Exactly the C++ string: ``D:P(A;;GA;;;SY)(A;;GA;;;`` + sid + ``)``.

    The SID text is validated first so no SDDL fragment (e.g. ``)(A;;GA;;;WD``)
    can be smuggled into the descriptor.
    """
    if type(sid_text) is not str or not _SID_TEXT.fullmatch(sid_text):
        raise ValueError('INVALID_SID_TEXT')
    return 'D:P(A;;GA;;;SY)(A;;GA;;;' + sid_text + ')'


def validate_deadline(deadline_s) -> float:
    if type(deadline_s) not in (int, float):          # rejects bool, str, None
        raise ValueError('INVALID_DEADLINE')
    value = float(deadline_s)
    if not math.isfinite(value) or value <= 0 or value > MAX_DEADLINE_S:
        raise ValueError('INVALID_DEADLINE')
    return value


def validate_pipe_name(name) -> str:
    if (type(name) is not str or not name.startswith(PIPE_PREFIX) or '\x00' in name
            or len(name) <= len(PIPE_PREFIX) or len(name) > 256 or '\\' in name[len(PIPE_PREFIX):]):
        raise ValueError('INVALID_PIPE_NAME')
    return name


@dataclass(frozen=True)
class PeerResult:
    verdict: str                     # 'PEER_OK' or 'DENIED'
    reason: str
    winerror: int | None = None
    client_pid: int | None = None
    client_sid: str | None = None
    impersonation_level: int | None = None
    response_sent: bool = False
    response_drained: bool = False
    elapsed_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.verdict == 'PEER_OK'


@dataclass(frozen=True)
class AceInfo:
    ace_type: int
    ace_flags: int
    mask: int
    sid: str


@dataclass(frozen=True)
class DaclInfo:
    protected: bool
    aces: tuple
    sddl: str


@dataclass(frozen=True)
class ClientResult:
    open_error: int | None
    response: bytes
    sent: bool
    reason: str = 'OK'
    winerror: int | None = None
    server_pid: int | None = None          # logged only, never a security decision
    pipe_owner: str | None = None


# --- ctypes binding ---------------------------------------------------------
if sys.platform == 'win32':
    from ctypes import wintypes

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [('Internal', ctypes.c_size_t), ('InternalHigh', ctypes.c_size_t),
                    ('Offset', wintypes.DWORD), ('OffsetHigh', wintypes.DWORD),
                    ('hEvent', wintypes.HANDLE)]

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('nLength', wintypes.DWORD), ('lpSecurityDescriptor', ctypes.c_void_p),
                    ('bInheritHandle', wintypes.BOOL)]

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', wintypes.DWORD)]

    class ACL_HEADER(ctypes.Structure):
        _fields_ = [('AclRevision', ctypes.c_ubyte), ('Sbz1', ctypes.c_ubyte),
                    ('AclSize', wintypes.WORD), ('AceCount', wintypes.WORD), ('Sbz2', wintypes.WORD)]

    class ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [('AceType', ctypes.c_ubyte), ('AceFlags', ctypes.c_ubyte),
                    ('AceSize', wintypes.WORD), ('Mask', wintypes.DWORD), ('SidStart', wintypes.DWORD)]

    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def _fn(dll, name, restype, *argtypes):
        f = getattr(dll, name)
        f.restype = restype
        f.argtypes = argtypes
        return f

    class WinApi:
        """Bound Win32 entry points. Tests may replace single attributes on an
        instance to inject faults; the default instance is never mutated."""

        def __init__(self):
            k = ctypes.WinDLL('kernel32', use_last_error=True)
            a = ctypes.WinDLL('advapi32', use_last_error=True)
            H, B, D, P = wintypes.HANDLE, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p
            self.CreateNamedPipeW = _fn(k, 'CreateNamedPipeW', H, wintypes.LPCWSTR, D, D, D, D, D, D, P)
            self.ConnectNamedPipe = _fn(k, 'ConnectNamedPipe', B, H, P)
            self.DisconnectNamedPipe = _fn(k, 'DisconnectNamedPipe', B, H)
            self.ReadFile = _fn(k, 'ReadFile', B, H, P, D, P, P)
            self.WriteFile = _fn(k, 'WriteFile', B, H, P, D, P, P)
            self.GetOverlappedResult = _fn(k, 'GetOverlappedResult', B, H, P, ctypes.POINTER(D), B)
            self.CancelIoEx = _fn(k, 'CancelIoEx', B, H, P)
            self.CreateEventW = _fn(k, 'CreateEventW', H, P, B, B, wintypes.LPCWSTR)
            self.WaitForSingleObject = _fn(k, 'WaitForSingleObject', D, H, D)
            self.CloseHandle = _fn(k, 'CloseHandle', B, H)
            self.GetNamedPipeClientProcessId = _fn(k, 'GetNamedPipeClientProcessId', B, H, ctypes.POINTER(wintypes.ULONG))
            self.GetNamedPipeServerProcessId = _fn(k, 'GetNamedPipeServerProcessId', B, H, ctypes.POINTER(wintypes.ULONG))
            self.CreateRestrictedToken = _fn(a, 'CreateRestrictedToken', B, H, D, D, P, D, P, D, P, ctypes.POINTER(H))
            self.GetSidSubAuthorityCount = _fn(a, 'GetSidSubAuthorityCount', ctypes.POINTER(ctypes.c_ubyte), P)
            self.GetSidSubAuthority = _fn(a, 'GetSidSubAuthority', ctypes.POINTER(D), P, D)
            self.GetCurrentProcess = _fn(k, 'GetCurrentProcess', H)
            self.GetCurrentThread = _fn(k, 'GetCurrentThread', H)
            self.LocalFree = _fn(k, 'LocalFree', P, P)
            self.CreateFileW = _fn(k, 'CreateFileW', H, wintypes.LPCWSTR, D, D, P, D, D, H)
            self.WaitNamedPipeW = _fn(k, 'WaitNamedPipeW', B, wintypes.LPCWSTR, D)
            self.OpenProcessToken = _fn(a, 'OpenProcessToken', B, H, D, ctypes.POINTER(H))
            self.OpenThreadToken = _fn(a, 'OpenThreadToken', B, H, D, B, ctypes.POINTER(H))
            self.GetTokenInformation = _fn(a, 'GetTokenInformation', B, H, ctypes.c_int, P, D, ctypes.POINTER(D))
            self.SetTokenInformation = _fn(a, 'SetTokenInformation', B, H, ctypes.c_int, P, D)
            self.DuplicateTokenEx = _fn(a, 'DuplicateTokenEx', B, H, D, P, ctypes.c_int, ctypes.c_int, ctypes.POINTER(H))
            self.SetThreadToken = _fn(a, 'SetThreadToken', B, P, H)
            self.ImpersonateNamedPipeClient = _fn(a, 'ImpersonateNamedPipeClient', B, H)
            self.RevertToSelf = _fn(a, 'RevertToSelf', B)
            self.EqualSid = _fn(a, 'EqualSid', B, P, P)
            self.IsValidSid = _fn(a, 'IsValidSid', B, P)
            self.ConvertSidToStringSidW = _fn(a, 'ConvertSidToStringSidW', B, P, ctypes.POINTER(wintypes.LPWSTR))
            self.ConvertStringSidToSidW = _fn(a, 'ConvertStringSidToSidW', B, wintypes.LPCWSTR, ctypes.POINTER(P))
            self.ConvertStringSecurityDescriptorToSecurityDescriptorW = _fn(
                a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', B,
                wintypes.LPCWSTR, D, ctypes.POINTER(P), ctypes.POINTER(wintypes.ULONG))
            self.ConvertSecurityDescriptorToStringSecurityDescriptorW = _fn(
                a, 'ConvertSecurityDescriptorToStringSecurityDescriptorW', B,
                P, D, D, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.ULONG))
            self.GetSecurityInfo = _fn(a, 'GetSecurityInfo', D, H, ctypes.c_int, D,
                                       ctypes.POINTER(P), P, ctypes.POINTER(P), P, ctypes.POINTER(P))
            self.GetSecurityDescriptorControl = _fn(a, 'GetSecurityDescriptorControl', B, P,
                                                    ctypes.POINTER(wintypes.WORD), ctypes.POINTER(D))
            self.GetAce = _fn(a, 'GetAce', B, P, D, ctypes.POINTER(P))
            self._terminate = _fn(k, 'TerminateProcess', B, H, wintypes.UINT)

        @staticmethod
        def last_error() -> int:
            return ctypes.get_last_error()

    _DEFAULT_API = None

    def default_api() -> 'WinApi':
        global _DEFAULT_API
        if _DEFAULT_API is None:
            _DEFAULT_API = WinApi()
        return _DEFAULT_API
else:  # pragma: no cover - exercised on non-Windows hosts
    def default_api():
        raise UnsupportedPlatform('WINDOWS_REQUIRED')


def _die_on_revert_failure() -> None:
    """C++: ``if (!RevertToSelf()) TerminateProcess(GetCurrentProcess(), 30);``
    Uses the real kernel32 (never the injectable api) so a faked API cannot
    suppress the termination."""
    try:
        k = ctypes.WinDLL('kernel32')
        k.GetCurrentProcess.restype = ctypes.c_void_p
        k.TerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_uint)
        k.TerminateProcess(k.GetCurrentProcess(), REVERT_FAILURE_EXIT)
    finally:
        os._exit(REVERT_FAILURE_EXIT)


# --- token helpers ----------------------------------------------------------
def _token_info(api, token, klass: int):
    """Return a ctypes buffer with the token information, or (None, err)."""
    required = wintypes.DWORD(0)
    api.GetTokenInformation(token, klass, None, 0, ctypes.byref(required))
    if required.value == 0 or required.value > TOKEN_INFO_MAX:
        return None, api.last_error() or ERROR_ACCESS_DENIED
    buf = ctypes.create_string_buffer(required.value)
    if not api.GetTokenInformation(token, klass, buf, required.value, ctypes.byref(required)):
        return None, api.last_error()
    return buf, 0


def _sid_ptr_from_token_user(api, buf):
    """TOKEN_USER.User.Sid; C++ query_sid also requires IsValidSid."""
    sid = ctypes.c_void_p.from_buffer(buf, 0).value
    if not sid or not api.IsValidSid(sid):
        return None
    return sid


def sid_to_text(api, sid) -> str:
    out = wintypes.LPWSTR()
    if not api.ConvertSidToStringSidW(sid, ctypes.byref(out)):
        raise OSError(api.last_error(), 'ConvertSidToStringSidW failed')
    try:
        return out.value
    finally:
        api.LocalFree(out)


def current_user_sid(api=None) -> str:
    api = api or default_api()
    tok = wintypes.HANDLE()
    if not api.OpenProcessToken(api.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)):
        raise OSError(api.last_error(), 'OpenProcessToken failed')
    try:
        buf, err = _token_info(api, tok, TokenUser)
        if buf is None:
            raise OSError(err, 'GetTokenInformation(TokenUser) failed')
        sid = _sid_ptr_from_token_user(api, buf)
        if sid is None:
            raise OSError(ERROR_ACCESS_DENIED, 'invalid token SID')
        return sid_to_text(api, sid)
    finally:
        api.CloseHandle(tok)


def thread_is_impersonating(api=None) -> bool:
    """True if the calling thread already holds a thread token."""
    api = api or default_api()
    tok = wintypes.HANDLE()
    if api.OpenThreadToken(api.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(tok)):
        api.CloseHandle(tok)
        return True
    # ERROR_NO_TOKEN is the only answer that proves "not impersonating".
    return api.last_error() != ERROR_NO_TOKEN


def _token_dword(api, token, klass: int):
    """DWORD-valued token information (SessionId, IsAppContainer, IsRestricted)."""
    buf, err = _token_info(api, token, klass)
    if buf is None or len(buf) < 4:
        return None, err or ERROR_ACCESS_DENIED
    return ctypes.c_uint32.from_buffer(buf, 0).value, 0


def _token_integrity_rid(api, token):
    """Last sub-authority of TOKEN_MANDATORY_LABEL.Label.Sid (e.g. 0x2000 Medium)."""
    buf, err = _token_info(api, token, TokenIntegrityLevel)
    if buf is None:
        return None, err
    sid = ctypes.c_void_p.from_buffer(buf, 0).value
    if not sid or not api.IsValidSid(sid):
        return None, ERROR_ACCESS_DENIED
    count = api.GetSidSubAuthorityCount(sid)
    if not count or count.contents.value == 0:
        return None, api.last_error() or ERROR_ACCESS_DENIED
    rid = api.GetSidSubAuthority(sid, count.contents.value - 1)
    if not rid:
        return None, api.last_error() or ERROR_ACCESS_DENIED
    return rid.contents.value, 0


def own_session_id(api=None) -> int:
    api = api or default_api()
    tok = wintypes.HANDLE()
    if not api.OpenProcessToken(api.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)):
        raise OSError(api.last_error(), 'OpenProcessToken failed')
    try:
        value, err = _token_dword(api, tok, TokenSessionId)
        if value is None:
            raise OSError(err, 'GetTokenInformation(TokenSessionId) failed')
        return value
    finally:
        api.CloseHandle(tok)


def inspect_dacl(handle, api=None) -> DaclInfo:
    """Read back the DACL actually attached to a kernel handle."""
    api = api or default_api()
    dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    rc = api.GetSecurityInfo(handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                             None, None, ctypes.byref(dacl), None, ctypes.byref(sd))
    if rc != 0:
        raise OSError(rc, 'GetSecurityInfo failed')
    try:
        control = wintypes.WORD()
        rev = wintypes.DWORD()
        if not api.GetSecurityDescriptorControl(sd, ctypes.byref(control), ctypes.byref(rev)):
            raise OSError(api.last_error(), 'GetSecurityDescriptorControl failed')
        aces = []
        if dacl.value:
            header = ACL_HEADER.from_address(dacl.value)
            for i in range(header.AceCount):
                p = ctypes.c_void_p()
                if not api.GetAce(dacl, i, ctypes.byref(p)):
                    raise OSError(api.last_error(), 'GetAce failed')
                ace = ACCESS_ALLOWED_ACE.from_address(p.value)
                sid_text = sid_to_text(api, p.value + ACCESS_ALLOWED_ACE.SidStart.offset)
                aces.append(AceInfo(ace.AceType, ace.AceFlags, ace.Mask, sid_text))
        text = wintypes.LPWSTR()
        if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, ctypes.byref(text), None):
            raise OSError(api.last_error(), 'ConvertSecurityDescriptorToStringSecurityDescriptorW failed')
        try:
            sddl = text.value
        finally:
            api.LocalFree(text)
        return DaclInfo(bool(control.value & SE_DACL_PROTECTED), tuple(aces), sddl)
    finally:
        api.LocalFree(sd)


# --- server -----------------------------------------------------------------
class _Timeout(Exception):
    pass


CANCEL_GRACE_MS = 1000
# I/O whose cancellation could not be confirmed within CANCEL_GRACE_MS: the
# kernel may still write into these objects, so they are kept alive. Entries
# whose event has meanwhile been signalled are pruned on the next park, so the
# list holds at most the I/Os that are concurrently stuck.
_PARKED: list = []
_PARKED_LOCK = threading.Lock()


def _park(api, ov, event, keepalive) -> None:
    with _PARKED_LOCK:
        still = []
        for entry in _PARKED:
            if api.WaitForSingleObject(entry[1], 0) == WAIT_OBJECT_0:
                api.CloseHandle(entry[1])
            else:
                still.append(entry)
        still.append((ov, event, keepalive))
        _PARKED[:] = still


def _overlapped_io(api, handle, start, deadline: float, *, lock=None, aborted=None, strict: bool = True):
    """Run one overlapped operation on ``handle``; return (ok, nbytes, winerror).

    Raises _Timeout when the absolute ``deadline`` passes (after cancelling the
    I/O and waiting a bounded grace). ``lock``/``aborted`` let a server make the
    abort check and the start of the I/O atomic with respect to close().
    ``strict=False`` reports an I/O that completed fully but after the deadline
    as completed (used for the response write: the bytes are already delivered).
    """
    if aborted is not None and aborted():
        return False, 0, ERROR_OPERATION_ABORTED
    event = api.CreateEventW(None, True, False, None)
    if not event:
        return False, 0, api.last_error()
    ov = OVERLAPPED()
    pending = False
    try:
        ov.hEvent = event
        n = wintypes.DWORD(0)
        # W13 (Aegis P2-b): ``pending`` is raised BEFORE start() and lowered only
        # once completion or cancellation is confirmed. Any other exit (exception,
        # async interrupt) is handled in ``finally``: cancel, bounded grace, park.
        # W13 (Aegis P2-c): abort check and I/O start are atomic w.r.t. close():
        # close() takes the same lock, so it either runs before (abort seen, no
        # I/O) or after the I/O was issued (its CancelIoEx then hits it).
        with (lock if lock is not None else contextlib.nullcontext()):
            if aborted is not None and aborted():
                return False, 0, ERROR_OPERATION_ABORTED
            pending = True
            started = start(ctypes.byref(ov))
        if started:
            pending = False
        else:
            err = api.last_error()
            if err != ERROR_IO_PENDING:
                pending = False
            if err == ERROR_PIPE_CONNECTED:              # connect raced ahead: success
                return True, 0, 0
            if err != ERROR_IO_PENDING:
                return False, 0, err
            # WaitForSingleObject may return WAIT_TIMEOUT a few ms BEFORE the
            # monotonic deadline (timer granularity; W12 measured up to 5.05 ms);
            # wait again for the rest so the deadline is never cut short.
            while True:
                remaining = deadline - time.monotonic()
                ms = 0 if remaining <= 0 else min(int(math.ceil(remaining * 1000)), INFINITE - 1)
                waited = api.WaitForSingleObject(event, ms)
                if waited != WAIT_TIMEOUT or remaining <= 0:
                    break
            if waited != WAIT_OBJECT_0:
                wait_err = 0 if waited == WAIT_TIMEOUT else (api.last_error() or ERROR_OPERATION_ABORTED)
                # Cancel, then wait a BOUNDED grace for the I/O to finish. Never
                # GetOverlappedResult(bWait=TRUE): if the cancel fails, that call
                # blocks until the peer acts (W12 measured 5.0 s for a 0.3 s
                # deadline). If the I/O is still pending, the OVERLAPPED, event
                # and buffer (held by ``start``) are parked, never freed under
                # the kernel; closing the pipe handle then aborts the I/O.
                api.CancelIoEx(handle, ctypes.byref(ov))
                if api.WaitForSingleObject(event, CANCEL_GRACE_MS) != WAIT_OBJECT_0:
                    _park(api, ov, event, start)
                    event = None
                pending = False                           # completed after cancel, or parked
                if waited == WAIT_TIMEOUT:
                    raise _Timeout()
                return False, 0, wait_err
            pending = False                               # event signalled: I/O finished
        if not api.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(n), False):
            return False, n.value, api.last_error()
        if strict and time.monotonic() >= deadline:
            raise _Timeout()                              # completed, but too late: strict
        return True, n.value, 0
    finally:
        if pending and event is not None:
            api.CancelIoEx(handle, ctypes.byref(ov))
            if api.WaitForSingleObject(event, CANCEL_GRACE_MS) != WAIT_OBJECT_0:
                _park(api, ov, event, start)
                event = None
        if event is not None:
            api.CloseHandle(event)


class OneShotPipeServer:
    """One pipe instance, one connection, one decision. Single use.

    ``expected_sid`` defaults to the current process user SID (C++ semantics).
    The DACL is ALWAYS SY + current process user; an override therefore can
    only narrow acceptance (or deny everything), never widen it.
    """

    def __init__(self, name: str = DEFAULT_PIPE_NAME, *, expected_sid: str | None = None, api=None):
        self._lock = threading.RLock()       # re-entrant: close() may run inside a locked region
        self._serving = False
        self._abort = False
        self._expected_bin = ctypes.c_void_p()
        self._api = api or default_api()
        self.name = validate_pipe_name(name)
        self._handle = None
        self._used = False
        api = self._api
        self.server_sid = current_user_sid(api)
        self._own_session = own_session_id(api)
        self.expected_sid = self.server_sid if expected_sid is None else expected_sid
        build_sddl(self.expected_sid)                    # syntax check of override
        self._expected_bin = ctypes.c_void_p()
        if not api.ConvertStringSidToSidW(self.expected_sid, ctypes.byref(self._expected_bin)):
            raise ValueError('INVALID_EXPECTED_SID')
        self.sddl = build_sddl(self.server_sid)
        sd = ctypes.c_void_p()
        try:
            if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    self.sddl, SDDL_REVISION_1, ctypes.byref(sd), None):
                raise PipeSetupError(api.last_error(), 'ConvertStringSecurityDescriptorToSecurityDescriptorW failed')
            sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
            pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS
            h = api.CreateNamedPipeW(self.name,
                                     PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                     pipe_mode, 1, 4096, 4096, 0, ctypes.byref(sa))
            if h is None or h == INVALID_HANDLE_VALUE:
                raise PipeSetupError(api.last_error(), 'CreateNamedPipeW failed')
            self._handle = h
        except BaseException:
            api.LocalFree(self._expected_bin)
            self._expected_bin = ctypes.c_void_p()
            raise
        finally:
            if sd.value:
                api.LocalFree(sd)

    @property
    def handle(self):
        return self._handle

    def close(self) -> None:
        """Idempotent and thread-safe. While serve() runs, close() only cancels
        its pending I/O; serve() releases handle and SID buffer in its own
        finally, so nothing is freed under a running operation (W12: a
        concurrent close previously caused STATUS_HEAP_CORRUPTION)."""
        api = self._api
        with self._lock:
            if self._serving:
                self._abort = True
                if self._handle is not None:
                    api.CancelIoEx(self._handle, None)
                return
            # W13 (Aegis P2-b): the field is cleared only AFTER CloseHandle, and
            # every step runs even if an earlier one raises. The lock is held, so
            # a second close() cannot see a half-released state.
            try:
                if self._handle is not None:
                    try:
                        api.DisconnectNamedPipe(self._handle)
                    finally:
                        try:
                            api.CloseHandle(self._handle)
                        finally:
                            self._handle = None
            finally:
                if self._expected_bin.value:
                    try:
                        api.LocalFree(self._expected_bin)
                    finally:
                        self._expected_bin = ctypes.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # -- overlapped I/O with an absolute deadline --
    def _io(self, start, deadline: float, strict: bool = True):
        return _overlapped_io(self._api, self._handle, start, deadline, lock=self._lock,
                              aborted=lambda: self._abort, strict=strict)

    def _impersonate_and_query(self):
        """Impersonate, read TokenImpersonationLevel + TokenUser, revert.
        Returns (reason|None, winerror, level, sid_bytes_buffer). Only ctypes
        calls run while impersonating; RevertToSelf failure kills the process."""
        api = self._api
        reason, err, level, user_buf, facts = None, 0, None, None, {}
        # W13 (Aegis P2-a): the impersonation call is INSIDE the try. An exception
        # landing right after it returns can no longer skip RevertToSelf; reverting
        # a thread that is not impersonating is harmless (serve() refuses to run
        # on a thread that already impersonates, so no outer identity is lost).
        try:
            if not api.ImpersonateNamedPipeClient(self._handle):
                return 'IMPERSONATE_FAILED', api.last_error(), None, None, {}
            tok = wintypes.HANDLE()
            if not api.OpenThreadToken(api.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(tok)):
                reason, err = 'OPEN_THREAD_TOKEN_FAILED', api.last_error()
            else:
                try:
                    lvl_buf, e1 = _token_info(api, tok, TokenImpersonationLevel)
                    user_buf, e2 = _token_info(api, tok, TokenUser)
                    # W13 (Quella F2): every identity fact comes from the TOKEN,
                    # never from GetNamedPipeClientProcessId/SessionId.
                    facts['integrity_rid'], e3 = _token_integrity_rid(api, tok)
                    facts['appcontainer'], e4 = _token_dword(api, tok, TokenIsAppContainer)
                    facts['restricted'], e5 = _token_dword(api, tok, TokenIsRestricted)
                    facts['session'], e6 = _token_dword(api, tok, TokenSessionId)
                    if lvl_buf is None or user_buf is None or None in facts.values():
                        reason, err = 'TOKEN_QUERY_FAILED', (e1 or e2 or e3 or e4 or e5 or e6)
                    else:
                        level = ctypes.c_int.from_buffer(lvl_buf, 0).value
                finally:
                    api.CloseHandle(tok)
        finally:
            if not api.RevertToSelf():
                _die_on_revert_failure()
        return reason, err, level, user_buf, facts

    def serve(self, deadline_s: float) -> PeerResult:
        budget = validate_deadline(deadline_s)
        with self._lock:
            if self._used:
                raise RuntimeError('SERVER_SINGLE_USE')
            self._used = True
            self._serving = True
        t0 = time.monotonic()
        deadline = t0 + budget
        api = self._api
        h = self._handle
        state = {'pid': None, 'sid': None, 'level': None, 'sent': False}

        def deny(reason, err=None):
            return PeerResult('DENIED', reason, err, state['pid'], state['sid'], state['level'],
                              state['sent'], False, time.monotonic() - t0)

        try:
            if h is None:
                return deny('NO_PIPE')
            if thread_is_impersonating(api):
                return deny('THREAD_ALREADY_IMPERSONATING')
            try:
                ok, _, err = self._io(lambda ov: api.ConnectNamedPipe(h, ov), deadline)
            except _Timeout:
                return deny('CONNECT_TIMEOUT')
            if not ok:
                return deny('CONNECT_FAILED', err)

            # C++: ImpersonateNamedPipeClient is based on the LAST message read.
            ping = ctypes.create_string_buffer(1)
            try:
                ok, count, err = self._io(lambda ov: api.ReadFile(h, ping, 1, None, ov), deadline)
            except _Timeout:
                return deny('READ_TIMEOUT')
            if not ok:
                return deny('READ_FAILED', err)
            if count != 1:
                return deny('SHORT_READ')

            pid = wintypes.ULONG(0)
            if not api.GetNamedPipeClientProcessId(h, ctypes.byref(pid)):
                return deny('CLIENT_PID_FAILED', api.last_error())
            state['pid'] = pid.value

            reason, err, level, user_buf, facts = self._impersonate_and_query()
            state['level'] = level
            if reason is not None:
                return deny(reason, err)
            client_sid = _sid_ptr_from_token_user(api, user_buf)
            if client_sid is None:
                return deny('INVALID_CLIENT_SID')
            state['sid'] = sid_to_text(api, client_sid)
            # W13 (E2 revised): the client grants only Identification, which is
            # all an identity check needs; Anonymous carries no identity.
            if level < SecurityIdentification:
                return deny('IMPERSONATION_LEVEL_TOO_LOW')
            if facts['integrity_rid'] < SECURITY_MANDATORY_MEDIUM_RID:
                return deny('INTEGRITY_TOO_LOW')
            if facts['appcontainer']:
                return deny('APPCONTAINER_CLIENT')
            if facts['restricted']:
                return deny('RESTRICTED_TOKEN')
            if facts['session'] != self._own_session:
                return deny('SESSION_MISMATCH')
            # C++: authorized = EqualSid(client_sid, server_sid)
            if not api.EqualSid(client_sid, self._expected_bin):
                return deny('SID_MISMATCH')
            if time.monotonic() >= deadline:
                return deny('DEADLINE_EXCEEDED')

            out = ctypes.create_string_buffer(RESPONSE, len(RESPONSE))
            try:
                ok, written, err = self._io(lambda ov: api.WriteFile(h, out, len(RESPONSE), None, ov), deadline)
            except _Timeout:
                return deny('WRITE_TIMEOUT')
            if not ok or written != len(RESPONSE):
                return deny('WRITE_FAILED', err)
            state['sent'] = True

            # Bounded replacement for FlushFileBuffers: wait for the client to
            # close (EOF) so DisconnectNamedPipe does not discard the response.
            drained = False
            sink = ctypes.create_string_buffer(1)
            try:
                ok, _, err = self._io(lambda ov: api.ReadFile(h, sink, 1, None, ov), deadline)
                drained = (not ok) and err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA)
            except _Timeout:
                drained = False
            return PeerResult('PEER_OK', 'OK', None, state['pid'], state['sid'], level,
                              True, drained, time.monotonic() - t0)
        finally:
            with self._lock:
                self._serving = False
            self.close()


# --- client (test/demo surface) ---------------------------------------------
def client_sqos_flags(level: str = 'identification') -> int:
    """dwFlagsAndAttributes SQOS part. Static tracking (no CONTEXT_TRACKING),
    EFFECTIVE_ONLY, and never Impersonation/Delegation (W13, Aegis P1-a)."""
    if level not in CLIENT_SQOS_LEVELS:
        raise ValueError('INVALID_LEVEL')
    return SECURITY_SQOS_PRESENT | CLIENT_SQOS_LEVELS[level] | SECURITY_EFFECTIVE_ONLY


def pipe_owner_sid(api, handle):
    """Owner SID pointer of the pipe object behind a CLIENT handle.
    Returns (owner c_void_p, security-descriptor c_void_p, 0) or (None, None, rc);
    the caller must LocalFree the descriptor (the owner points into it)."""
    owner = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    rc = api.GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                             ctypes.byref(owner), None, None, None, ctypes.byref(sd))
    if rc != 0:
        return None, None, rc
    return owner, sd, 0


def _verify_pipe_owner(api, handle, expected_bin):
    """Decision: owner of the pipe object == expected SID (Forshaw 2019: the
    server PID must not be relied upon for security decisions)."""
    owner, sd, rc = pipe_owner_sid(api, handle)
    if owner is None:
        return 'PIPE_OWNER_FAILED', rc, None
    try:
        if not owner.value or not api.IsValidSid(owner):
            return 'PIPE_OWNER_FAILED', ERROR_ACCESS_DENIED, None
        try:
            text = sid_to_text(api, owner)
        except OSError:
            text = None
        if not api.EqualSid(owner, expected_bin):
            return 'PIPE_OWNER_MISMATCH', 0, text
        return None, 0, text
    finally:
        if sd.value:
            api.LocalFree(sd)


def client_ping(name: str = DEFAULT_PIPE_NAME, *, level: str = 'identification',
                send: bool = True, hold_s: float = 0.0, connect_timeout_s: float = 5.0,
                response_timeout_s: float = 5.0, expected_server_sid: str | None = None,
                api=None) -> ClientResult:
    """Port of udx_sid_client.cpp (W13 protocol).

    * SQOS: Identification + EFFECTIVE_ONLY, static tracking (never Impersonation)
    * BEFORE the first write: the pipe object's owner must equal
      ``expected_server_sid`` (default: this process' user SID); otherwise no
      byte is sent and a typed reason is returned. The server PID is logged only.
    * write and read run with an absolute deadline (``response_timeout_s``).
    ``send=False`` connects, verifies and stays silent for ``hold_s`` seconds.
    """
    api = api or default_api()
    # Local names are fully validated; '\\host\pipe\...' is allowed for the
    # SMB-redirector negative test (PIPE_REJECT_REMOTE_CLIENTS).
    if type(name) is not str or '\x00' in name or not name.startswith('\\\\'):
        raise ValueError('INVALID_PIPE_NAME')
    if name.startswith(PIPE_PREFIX):
        validate_pipe_name(name)
    flags = client_sqos_flags(level) | FILE_FLAG_OVERLAPPED
    end = time.monotonic() + validate_deadline(connect_timeout_s)
    budget = validate_deadline(response_timeout_s)
    expected = current_user_sid(api) if expected_server_sid is None else expected_server_sid
    build_sddl(expected)                                  # SID syntax check
    expected_bin = ctypes.c_void_p()
    if not api.ConvertStringSidToSidW(expected, ctypes.byref(expected_bin)):
        raise ValueError('INVALID_EXPECTED_SID')
    try:
        while True:
            h = api.CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, flags, None)
            if h is not None and h != INVALID_HANDLE_VALUE:
                break
            err = api.last_error()
            if err not in (ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY) or time.monotonic() >= end:
                return ClientResult(err, b'', False, 'OPEN_FAILED', err)
            time.sleep(0.02)
        try:
            spid = wintypes.ULONG(0)
            server_pid = spid.value if api.GetNamedPipeServerProcessId(h, ctypes.byref(spid)) else None
            reason, err, owner_text = _verify_pipe_owner(api, h, expected_bin)
            if reason is not None:
                return ClientResult(None, b'', False, reason, err, server_pid, owner_text)
            if not send:
                time.sleep(hold_s)
                return ClientResult(None, b'', False, 'SILENT_HOLD', None, server_pid, owner_text)
            deadline = time.monotonic() + budget
            ping = ctypes.create_string_buffer(b'\x55', 1)
            try:
                ok, n, err = _overlapped_io(api, h, lambda ov: api.WriteFile(h, ping, 1, None, ov), deadline)
            except _Timeout:
                return ClientResult(None, b'', False, 'WRITE_TIMEOUT', None, server_pid, owner_text)
            if not ok or n != 1:
                return ClientResult(None, b'', False, 'WRITE_FAILED', err, server_pid, owner_text)
            # C++ client reads exactly 7 bytes, then closes.
            data = b''
            buf = ctypes.create_string_buffer(len(RESPONSE))
            while len(data) < len(RESPONSE):
                want = len(RESPONSE) - len(data)
                try:
                    ok, got, err = _overlapped_io(api, h, lambda ov: api.ReadFile(h, buf, want, None, ov), deadline)
                except _Timeout:
                    return ClientResult(None, data, True, 'READ_TIMEOUT', None, server_pid, owner_text)
                if not ok or got == 0:
                    return ClientResult(None, data, True, 'READ_FAILED', err, server_pid, owner_text)
                data += buf.raw[:got]
            reason = 'OK' if data == RESPONSE else 'BAD_RESPONSE'
            return ClientResult(None, data, True, reason, None, server_pid, owner_text)
        finally:
            api.CloseHandle(h)
    finally:
        api.LocalFree(expected_bin)


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(description='UDX W12 Windows pipe peer-SID probe (research only)')
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('server')
    s.add_argument('--name', default=DEFAULT_PIPE_NAME)
    s.add_argument('--deadline', type=float, default=10.0)
    c = sub.add_parser('client')
    c.add_argument('--name', default=DEFAULT_PIPE_NAME)
    c.add_argument('--level', default='identification', choices=sorted(CLIENT_SQOS_LEVELS))
    c.add_argument('--silent-hold', type=float, default=None)
    args = p.parse_args(argv)
    if args.cmd == 'server':
        with OneShotPipeServer(args.name) as srv:
            print(json.dumps({'listening': srv.name}), flush=True)
            r = srv.serve(args.deadline)
        print(json.dumps(asdict(r)), flush=True)
        return 0 if r.ok else 20                       # C++ exit codes 0 / 20
    r = client_ping(args.name, level=args.level, send=args.silent_hold is None,
                    hold_s=args.silent_hold or 0.0)
    print(json.dumps({'open_error': r.open_error, 'response': r.response.decode('latin-1'),
                      'sent': r.sent, 'reason': r.reason, 'pid': os.getpid()}), flush=True)
    return 0 if r.response == RESPONSE else 3          # C++ client exit codes 0 / 3


if __name__ == '__main__':
    sys.exit(main())
