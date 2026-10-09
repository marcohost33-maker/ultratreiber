"""UDX W8 Linux *private trusted-host* descriptor handoff research candidate.

No named/listening socket; no filesystem paths in the wire protocol; exact one
SCM_RIGHTS descriptor required. The host must already have obtained an OS/user
approved O_RDONLY fd, which THIS MODULE CANNOT VERIFY. No new capability is
registered on the publicly accessible UDX fixture IPC. This is not an app
identity, FileChooser, consent, privilege, or atomic-source-snapshot proof.
"""
from __future__ import annotations
import array
import hashlib
import json
import os
import socket
import struct
import sys
import uuid
from .fd_reader import ReadGuardError, MAX_READ
from .sealed_snapshot import SealedSnapshot

PROTOCOL = 'udx/fd/0.1'
OPERATION = 'inspect.readonly'
MAX_WIRE = 256
MAX_STATUS = 320
_UCRED = struct.Struct('3i')

class HandoffError(ValueError):
    pass


def supported():
    return (sys.platform == 'linux' and hasattr(socket, 'SO_PEERCRED')
            and hasattr(socket, 'SOCK_SEQPACKET') and hasattr(socket, 'SCM_RIGHTS')
            and hasattr(socket, 'MSG_CMSG_CLOEXEC'))


def private_pair():
    if not supported():
        raise HandoffError('UNSUPPORTED_PLATFORM')
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    a.set_inheritable(False)
    b.set_inheritable(False)
    for s in (a,b):
        s.settimeout(2.0)
    return a,b


def _canonical_uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value and len(value) == 36
    except (ValueError, TypeError, AttributeError):
        return False


def _pairs(pairs):
    out = {}
    for k,v in pairs:
        if k in out:
            raise HandoffError('DUPLICATE_FIELD')
        out[k] = v
    return out


def _decode(data):
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise HandoffError('MALFORMED_WIRE') from exc


def _peer_uid(sock):
    if not supported() or sock.family != socket.AF_UNIX or sock.type & 0xf != socket.SOCK_SEQPACKET:
        raise HandoffError('BAD_TRANSPORT')
    try:
        pid, uid, gid = _UCRED.unpack(sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size))
    except (OSError, struct.error) as exc:
        raise HandoffError('NO_OS_PEER') from exc
    if pid <= 0 or uid < 0 or gid < 0:
        raise HandoffError('NO_OS_PEER')
    # On socketpair(), SO_PEERCRED can reflect credentials AT PAIR CREATION,
    # and must NOT be misrepresented as authentication of a spawned child PID.
    return uid


def send_approved_fd(sock, fd, request_id):
    """Trusted host side only; never callable from the public UDX IPC."""
    if type(fd) is not int or fd < 0 or not _canonical_uuid(request_id):
        raise HandoffError('BAD_ARGUMENT')
    message = json.dumps({'v': PROTOCOL, 'op': OPERATION, 'id': request_id},
                         sort_keys=True, separators=(',', ':')).encode()
    if len(message) > MAX_WIRE:
        raise HandoffError('SIZE_LIMIT')
    sent = sock.sendmsg([message], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i',[fd]))])
    if sent != len(message):
        raise HandoffError('PARTIAL_SEND')


def _recv_fd(sock, expected_uid):
    """Receive/close *all* transferred descriptors on ANY malformed packet."""
    if type(expected_uid) is not int or expected_uid < 0 or _peer_uid(sock) != expected_uid:
        raise HandoffError('PEER_UID_MISMATCH')
    received = []
    try:
        data, anc, flags, _ = sock.recvmsg(MAX_WIRE, socket.CMSG_SPACE(4 * array.array('i').itemsize),
                                           socket.MSG_CMSG_CLOEXEC)
        invalid_ancillary = False
        for lvl, kind, payload in anc:
            if lvl != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                invalid_ancillary = True
                continue
            width = array.array('i').itemsize
            if not payload or len(payload)%width:
                invalid_ancillary = True
                continue
            ints = array.array('i')
            ints.frombytes(payload)
            received.extend(ints.tolist())
        if invalid_ancillary:
            raise HandoffError('BAD_ANCILLARY')
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise HandoffError('TRUNCATED_PACKET')
        if not data or len(received) != 1:
            raise HandoffError('EXPECTED_EXACTLY_ONE_FD')
        if os.get_inheritable(received[0]):
            raise HandoffError('CLOEXEC_REQUIRED')
        obj = _decode(data)
        if type(obj) is not dict or set(obj) != {'v','op','id'} or obj['v'] != PROTOCOL or obj['op'] != OPERATION or not _canonical_uuid(obj['id']):
            raise HandoffError('INVALID_ENVELOPE')
        return obj['id'], received.pop()
    finally:
        for fd in received:
            try: os.close(fd)
            except OSError: pass


def handle_once(sock, *, expected_uid, owner_uid, limit=MAX_READ):
    """Read ONLY a host-provided FD; publish digest+size, NEVER source bytes."""
    if type(owner_uid) is not int or owner_uid < 0 or type(limit) is not int or not 1 <= limit <= MAX_READ:
        raise HandoffError('INVALID_HOST_POLICY')
    request_id, fd = _recv_fd(sock, expected_uid)
    try:
        with SealedSnapshot(fd, expected_uid=owner_uid, limit=limit) as snap:
            data = snap.read()
        answer = {'v': PROTOCOL, 'id': request_id, 'status': 'SEALED_METADATA',
                  'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    finally:
        os.close(fd)
    raw = json.dumps(answer, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(raw) > MAX_STATUS or sock.send(raw) != len(raw):
        raise HandoffError('REPLY_FAILED')
    return answer


def recv_status(sock, expected_request_id):
    """Requester checks message identity and digest syntax, not just success."""
    if not _canonical_uuid(expected_request_id):
        raise HandoffError('BAD_ARGUMENT')
    data, anc, flags, _ = sock.recvmsg(MAX_STATUS, socket.CMSG_SPACE(array.array('i').itemsize),
                                       socket.MSG_CMSG_CLOEXEC)
    fd_list=[]
    try:
        for lvl,kind,payload in anc:
            if lvl==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                ints=array.array('i')
                ints.frombytes(payload[:len(payload)//ints.itemsize*ints.itemsize])
                fd_list.extend(ints)
        if fd_list or anc or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise HandoffError('BAD_RESPONSE_CONTROL')
        obj=_decode(data)
        if type(obj) is not dict or set(obj) != {'v','id','status','size','sha256'}:
            raise HandoffError('BAD_RESPONSE')
        if obj['v'] != PROTOCOL or obj['id'] != expected_request_id or obj['status'] != 'SEALED_METADATA':
            raise HandoffError('RESPONSE_SCOPE_MISMATCH')
        if type(obj['size']) is not int or not 0 <= obj['size'] <= MAX_READ:
            raise HandoffError('RESPONSE_SIZE')
        digest=obj['sha256']
        if type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise HandoffError('BAD_RESPONSE_DIGEST')
        return obj
    finally:
        for fd in fd_list:
            try: os.close(fd)
            except OSError:pass
