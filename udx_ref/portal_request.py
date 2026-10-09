"""W10 fail-closed correlation state machine for a FUTURE authenticated D-Bus integration.

Important: no D-Bus transport runs here. Values passed to receive() are TRUSTED
only if provided by a real D-Bus library, never by JSON from UDX clients.
This module is not a consent authority and does not mint grants.
"""
from __future__ import annotations
import re
import secrets
import time
import math
from .portal_boundary import validate_chooser_result

class PortalFlowError(RuntimeError):pass
_NAME = re.compile(r'^:[0-9]+(?:\.[0-9]+)+$')
_TOKEN = re.compile(r'^[a-zA-Z0-9_]{16,80}$')
_HANDLE = re.compile(r'^/org/freedesktop/portal/desktop/request/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+$')

class PortalRequest:
    def __init__(self, *, caller_unique: str, portal_owner_unique: str, ttl_seconds: float=120., clock=None):
        if not isinstance(caller_unique,str) or not _NAME.fullmatch(caller_unique):raise PortalFlowError('BAD_CALLER_NAME')
        if not isinstance(portal_owner_unique,str) or not _NAME.fullmatch(portal_owner_unique):raise PortalFlowError('BAD_PORTAL_OWNER')
        if type(ttl_seconds) not in (float,int) or not 1<=ttl_seconds<=300:raise PortalFlowError('BAD_DEADLINE')
        self._clock=clock if clock is not None else time.monotonic
        start=self._checked_clock()
        self._last_clock=start
        self._deadline=start+ttl_seconds
        if not math.isfinite(self._deadline):
            raise PortalFlowError('BAD_CLOCK')
        self._owner=portal_owner_unique
        self._token='udx_'+secrets.token_hex(16)
        sender=caller_unique[1:].replace('.','_')
        self.handle=f'/org/freedesktop/portal/desktop/request/{sender}/{self._token}'
        self.state='AWAITING_REPLY'
    def _checked_clock(self):
        try:
            now=self._clock()
        except Exception as e:
            raise PortalFlowError('CLOCK_FAILED') from e
        if type(now) not in (float,int) or not math.isfinite(now) or now < 0:
            raise PortalFlowError('BAD_CLOCK')
        return now

    @property
    def request_options(self):return {'handle_token':self._token,'multiple':False,'writable':False}
    def bind_handle(self, returned: str):
        if self.state !='AWAITING_REPLY':raise PortalFlowError('NOT_AWAITING')
        if type(returned) is not str or not _HANDLE.fullmatch(returned) or returned!=self.handle:
            self.state='REJECTED'
            raise PortalFlowError('HANDLE_MISMATCH')
        self.state='AWAITING_RESPONSE'
    def cancel(self):
        if self.state not in ('AWAITING_REPLY','AWAITING_RESPONSE'):raise PortalFlowError('TOO_LATE')
        self.state='CANCELLED'
        # Real integration must ALSO invoke Request.Close via authenticated D-Bus.
    def receive(self, *, sender_unique: str, signal_path: str, response_code: int, results: dict):
        if self.state!='AWAITING_RESPONSE':raise PortalFlowError('NOT_EXPECTING_RESPONSE')
        try:
            now=self._checked_clock()
        except PortalFlowError:
            self.state='REJECTED'
            raise
        if now < self._last_clock:
            self.state='REJECTED'
            raise PortalFlowError('CLOCK_ROLLBACK')
        self._last_clock=now
        if now >= self._deadline:
            self.state='EXPIRED';raise PortalFlowError('TIMEOUT')
        if sender_unique!=self._owner or signal_path!=self.handle:
            self.state='REJECTED';raise PortalFlowError('PROVENANCE_MISMATCH')
        try:
            uri=validate_chooser_result(response_code,results)
        except ValueError as e:
            self.state='REJECTED';raise PortalFlowError('DENIED_OR_MALFORMED') from e
        self.state='RESULT_OBSERVED'
        # An URI is only an observed choice, not a revocable FD nor app grant.
        return uri
