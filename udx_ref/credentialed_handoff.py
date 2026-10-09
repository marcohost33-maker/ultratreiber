"""W9 research-only credentialed private FD handoff for Linux.

SCM_CREDENTIALS is evaluated ON EACH RECEIVED MESSAGE. Unlike SO_PEERCRED
on socketpair, it reflects message-time sender credentials. The channel is
preconnected/private and must be inherited solely by an appropriately isolated
host and worker. No public network/listening socket or filesystem paths.

CAUTION: UID does not disambiguate same-UID apps; privileged senders may
supply alternate credentials under kernel rules. Credential checks are not
user consent or an OS sandbox. A received FD outlives a permission revocation.
"""
from __future__ import annotations
import array
import hashlib
import json
import os
import socket
import struct
import sys
from .fd_handoff import (HandoffError, _canonical_uuid, _decode,
                         OPERATION, PROTOCOL, MAX_WIRE, MAX_STATUS)
from .sealed_snapshot import SealedSnapshot
from .fd_reader import MAX_READ

_CRED = struct.Struct('3i')
_FD_ITEMSIZE = array.array('i').itemsize


def available():
    return (sys.platform == 'linux' and hasattr(socket, 'SCM_CREDENTIALS')
            and hasattr(socket, 'SO_PASSCRED') and hasattr(socket, 'SOCK_SEQPACKET')
            and hasattr(socket, 'MSG_CMSG_CLOEXEC'))


def credentialed_pair():
    """Create a one-shot private pair; no address anyone can connect to."""
    if not available():
        raise HandoffError('UNSUPPORTED_PLATFORM')
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    for sock in (left, right):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        sock.settimeout(2.0)
        sock.set_inheritable(False)
    return left, right


def _check_socket(sock):
    if not available() or sock.family != socket.AF_UNIX or sock.type & 15 != socket.SOCK_SEQPACKET:
        raise HandoffError('BAD_TRANSPORT')
    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
        raise HandoffError('PASSCRED_REQUIRED')


def _receive(sock, max_bytes: int, *, expected_uid: int, expect_fd: bool):
    _check_socket(sock)
    if type(expected_uid) is not int or expected_uid < 0:
        raise HandoffError('INVALID_IDENTITY_POLICY')
    transferred = []
    try:
        data, ancillary, flags, _ = sock.recvmsg(
            max_bytes, socket.CMSG_SPACE(_FD_ITEMSIZE * 4) + socket.CMSG_SPACE(_CRED.size),
            socket.MSG_CMSG_CLOEXEC)
        creds = []
        bad = False
        for level, kind, content in ancillary:
            if level != socket.SOL_SOCKET:
                bad = True
            elif kind == socket.SCM_RIGHTS:
                if not content or len(content) % _FD_ITEMSIZE:
                    bad = True
                else:
                    fds = array.array('i')
                    fds.frombytes(content)
                    transferred.extend(fds)
            elif kind == socket.SCM_CREDENTIALS:
                if len(content) != _CRED.size:
                    bad = True
                else:
                    creds.append(_CRED.unpack(content))
            else:
                bad = True
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise HandoffError('TRUNCATED_PACKET')
        if bad or len(creds) != 1 or creds[0][0] <= 0 or creds[0][1] != expected_uid:
            raise HandoffError('CREDENTIALS_MISMATCH')
        if not data or len(transferred) != (1 if expect_fd else 0):
            raise HandoffError('FD_CARDINALITY')
        if transferred and os.get_inheritable(transferred[0]):
            raise HandoffError('CLOEXEC_REQUIRED')
        fd = transferred.pop() if expect_fd else None
        return data, fd, creds[0]
    finally:
        for fd in transferred:
            try: os.close(fd)
            except OSError: pass


def send_readonly_request(sock, fd: int, request_id: str):
    """Trusted host only; host must obtain legitimate grant before calling."""
    _check_socket(sock)
    if type(fd) is not int or fd < 0 or not _canonical_uuid(request_id):
        raise HandoffError('BAD_ARGUMENT')
    payload = json.dumps({'v': PROTOCOL, 'op': OPERATION, 'id': request_id},
                         separators=(',', ':'), sort_keys=True).encode('ascii')
    if len(payload) > MAX_WIRE:
        raise HandoffError('SIZE_LIMIT')
    sent = sock.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
    if sent != len(payload):
        raise HandoffError('PARTIAL_SEND')


def process_one(sock, *, expected_sender_uid: int, source_owner_uid: int,
                limit: int = MAX_READ):
    """Worker executes one metadata-only operation; never returns source bytes."""
    if type(source_owner_uid) is not int or source_owner_uid < 0 or type(limit) is not int or not 1 <= limit <= MAX_READ:
        raise HandoffError('INVALID_HOST_POLICY')
    payload, fd, _cred = _receive(sock, MAX_WIRE, expected_uid=expected_sender_uid, expect_fd=True)
    try:
        obj = _decode(payload)
        if (type(obj) is not dict or set(obj) != {'v', 'op', 'id'} or
            obj.get('v') != PROTOCOL or obj.get('op') != OPERATION or
            not _canonical_uuid(obj.get('id'))):
            raise HandoffError('INVALID_ENVELOPE')
        with SealedSnapshot(fd, expected_uid=source_owner_uid, limit=limit) as snap:
            content = snap.read()
        result = {'v': PROTOCOL, 'id': obj['id'], 'status': 'SEALED_METADATA',
                  'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
    finally:
        os.close(fd)
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > MAX_STATUS or sock.send(encoded) != len(encoded):
        raise HandoffError('REPLY_FAILED')
    return result


def read_verified_reply(sock, *, expected_worker_uid: int, request_id: str):
    if not _canonical_uuid(request_id):
        raise HandoffError('BAD_ARGUMENT')
    data, _, _ = _receive(sock, MAX_STATUS, expected_uid=expected_worker_uid, expect_fd=False)
    parsed = _decode(data)
    if (type(parsed) is not dict or set(parsed) != {'v','id','status','size','sha256'}
        or parsed['v'] != PROTOCOL or parsed['id'] != request_id
        or parsed['status'] != 'SEALED_METADATA' or type(parsed['size']) is not int
        or not 0 <= parsed['size'] <= MAX_READ):
        raise HandoffError('INVALID_REPLY')
    digest = parsed['sha256']
    if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise HandoffError('INVALID_REPLY_DIGEST')
    return parsed
