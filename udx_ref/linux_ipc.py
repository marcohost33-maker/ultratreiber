"""Linux-only, same-UID AF_UNIX stream transport for read-only fixture broker.

Research prototype. Authenticates Linux UID via SO_PEERCRED (not JSON payload).
Does not support writable file access, arbitrary paths, remote access or root service.
"""
from __future__ import annotations
import argparse
import os
import socket
import stat
import time
import struct
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
from pathlib import Path
from .core import Broker, FixtureAdapter, ObjectMetadata, PeerIdentity, Policy, MAX_MESSAGE_BYTES, Refusal, VERSION, decode_request, decode_response

HEADER = struct.Struct('!I')
UCRED = struct.Struct('3i')
MAX_RESPONSE_BYTES = 4096
MAX_WORKERS = 4
REQUEST_DEADLINE_S = 1.0


def supported():
    return sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED')


def peer_identity(conn):
    if not supported() or conn.family != socket.AF_UNIX:
        raise Refusal('UNAUTHENTICATED_PEER')
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size)
        if len(raw) != UCRED.size:
            raise Refusal('UNAUTHENTICATED_PEER')
        pid, uid, gid = UCRED.unpack(raw)
        if pid <= 0 or uid < 0 or gid < 0:
            raise Refusal('UNAUTHENTICATED_PEER')
    except (OSError, struct.error) as exc:
        raise Refusal('UNAUTHENTICATED_PEER') from exc
    return PeerIdentity(subject=f'uid:{uid}', authenticated=True)


def recv_exact(conn, size, *, deadline=None):
    chunks = []
    while size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('full-request deadline exceeded')
            conn.settimeout(remaining)
        part = conn.recv(size)
        if not part:
            raise ConnectionError('truncated frame')
        chunks.append(part)
        size -= len(part)
    return b''.join(chunks)


def send_frame(conn, response):
    from json import dumps
    raw = dumps(response, separators=(',', ':'), sort_keys=True, ensure_ascii=True).encode('utf-8')
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError('response exceeds budget')
    conn.sendall(HEADER.pack(len(raw)) + raw)


def serve_connection(conn, broker):
    """At most one request per connection; no caller-supplied subject accepted."""
    # Absolute budget avoids indefinite trickle attacks against a serial broker.
    deadline = time.monotonic() + REQUEST_DEADLINE_S
    conn.settimeout(REQUEST_DEADLINE_S)
    try:
        peer = peer_identity(conn)
    except Refusal:
        return
    try:
        size = HEADER.unpack(recv_exact(conn, HEADER.size, deadline=deadline))[0]
        if size > MAX_MESSAGE_BYTES:
            raw = b'x' * (MAX_MESSAGE_BYTES + 1)  # rejection WITHOUT reading attacker body
        else:
            raw = recv_exact(conn, size, deadline=deadline)
        answer = broker.handle(raw, peer)
        send_frame(conn, answer)
    except (ConnectionError, OSError, TimeoutError, ValueError, struct.error):
        # No operation has OS side effects. Malformed/truncated frames close the connection.
        return


def verify_directory(runtime_dir):
    base = Path(runtime_dir)
    if not base.is_absolute() or base.is_symlink() or base.resolve(strict=True) != base:
        raise PermissionError('runtime directory must be absolute, canonical and not a symlink')
    details = base.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
        raise PermissionError('runtime directory is not owned by server UID')
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise PermissionError('runtime directory must have exactly mode 0700')
    if len(os.fsencode(str(base / 'udx.sock'))) >= 104:
        raise ValueError('AF_UNIX socket pathname too long for portable Linux tests')
    return base


def serve_forever(runtime_dir, *, max_connections=0):
    """Dedicated non-root, single-thread reference daemon; pre-created private directory required.

    max_connections=0 means until signal. A bounded value is useful for tests.
    """
    if not supported() or os.geteuid() == 0:
        raise RuntimeError('Linux unprivileged execution required')
    base = verify_directory(runtime_dir)
    path = base / 'udx.sock'
    if os.path.lexists(path):
        raise FileExistsError('refusing to overwrite preexisting socket/path')
    owner = f'uid:{os.geteuid()}'
    broker = Broker(FixtureAdapter({'sample-1': ObjectMetadata('sample-1', owner, 42, 'fixture')}),
                    Policy({owner: {'udx.discover', 'udx.metadata.read'}}))
    own_inode = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        try:
            # Isolated dedicated process: umask 077 BEFORE filesystem socket bind.
            prior_mask = os.umask(0o077)
            try:
                listener.bind(str(path))
            finally:
                os.umask(prior_mask)
            details = path.lstat()
            own_inode = (details.st_dev, details.st_ino)
            os.chmod(path, 0o600)
            listener.listen(8)
            # A bounded pool avoids a single slow client serializing all peers.
            # No unbounded executor queue: reject immediately when capacity is full.
            slots = BoundedSemaphore(MAX_WORKERS)
            def task(conn):
                try:
                    with conn:
                        serve_connection(conn, broker)
                finally:
                    slots.release()
            count = 0
            with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='udx-ipc') as pool:
                while max_connections == 0 or count < max_connections:
                    conn, _ = listener.accept()
                    count += 1
                    if slots.acquire(blocking=False):
                        try:
                            pool.submit(task, conn)
                        except BaseException:
                            conn.close()
                            slots.release()
                            raise
                    else:
                        # Fail closed on saturation. Do not queue unbounded work.
                        conn.close()
        finally:
            if own_inode is not None:
                try:
                    current = path.lstat()
                    if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == own_inode:
                        path.unlink()
                except FileNotFoundError:
                    pass


def request_on_socket(path, raw, *, timeout=1.5):
    """Demo client: any local process in same UID may connect. No privileged calls."""
    import json
    if type(raw) is not bytes or len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError('request too large or wrong type')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(path))
        # This authenticates the service at Linux UID granularity only. It does not
        # distinguish processes of the same UID or offer software attestation.
        service = peer_identity(conn)
        if service.subject != f'uid:{os.geteuid()}':
            raise PermissionError('socket peer is not the expected local UID')
        deadline = time.monotonic() + timeout
        conn.sendall(HEADER.pack(len(raw)) + raw)
        size = HEADER.unpack(recv_exact(conn, HEADER.size, deadline=deadline))[0]
        if size > MAX_RESPONSE_BYTES:
            raise ValueError('oversized response')
        reply = recv_exact(conn, size, deadline=deadline)
        try:
            sent = decode_request(raw)
        except Refusal:
            sent = None
        return decode_response(reply, expected_request_id=sent['request_id'] if sent else None,
                               expected_capability=sent['capability'] if sent else None,
                               expected_params=sent['params'] if sent else None)


def main():
    ap = argparse.ArgumentParser(description='UDX Linux read-only research fixture server')
    ap.add_argument('--runtime-dir', required=True)
    ap.add_argument('--max-connections', type=int, default=0)
    args = ap.parse_args()
    if args.max_connections < 0 or args.max_connections > 1000:
        ap.error('invalid max-connections')
    serve_forever(args.runtime_dir, max_connections=args.max_connections)


if __name__ == '__main__':
    main()
