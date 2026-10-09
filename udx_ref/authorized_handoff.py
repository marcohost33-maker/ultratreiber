"""Private trusted-host W10 one-time FD handoff, no public UDX entry point.

The caller MUST hold kernel-verified credentials and obtain legitimate consent
outside this module. Claim is DURABLY committed before SCM_RIGHTS transmission.
Interrupted/failed exchange is quarantined, NEVER automatically retried.
"""
from __future__ import annotations
from .credentialed_handoff import send_readonly_request,read_verified_reply
from .durable_grants import GrantDenied

def perform_trusted_handoff(store, sock, fd: int, *, grant_id: str,
                           issuer_uid: int, worker_uid: int, request_id: str):
    store.claim(grant_id,fd,issuer_uid=issuer_uid,recipient_uid=worker_uid,request_id=request_id)
    try:
        send_readonly_request(sock,fd,request_id)
        response=read_verified_reply(sock,expected_worker_uid=worker_uid,request_id=request_id)
        store.finish(grant_id,request_id)
        return response
    except BaseException:
        try:store.quarantine(grant_id)
        except Exception:pass
        raise
