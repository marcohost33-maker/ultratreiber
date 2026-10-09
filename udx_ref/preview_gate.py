"""W6 *in-process* dry-run gate. Research fixture, NOT an authorization boundary.

The issuer is a trusted-test-harness interface, not remotely callable. No
operating-system events are emitted; no screenshot capture or input injection.
"""
from __future__ import annotations
from dataclasses import dataclass
from threading import RLock
from time import monotonic
from uuid import UUID, uuid4
from collections import deque
import re
import math

MAX_TTL_SECONDS = 60.0
MAX_GRANTS = 128
MAX_EVENTS = 256
MAX_SEEN = 4096
_SAFE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}\Z', re.ASCII)
CAPABILITY = 'input.pointer.preview'  # mock only; never a physical OS input capability

class GateError(ValueError):
    pass

def _token(s: str) -> bool:
    return type(s) is str and _SAFE.fullmatch(s) is not None

def _uuid(s: str) -> bool:
    try:
        return type(s) is str and str(UUID(s)) == s and len(s) == 36
    except (ValueError, TypeError, AttributeError):
        return False

@dataclass(frozen=True)
class PreviewProposal:
    request_id: str
    principal: str
    session_id: str
    resource_id: str
    frame_epoch: int
    width: int
    height: int
    x: int
    y: int
    capability: str = CAPABILITY

@dataclass(frozen=True)
class GateResult:
    code: str
    accepted: bool
    effect: str = 'NONE'  # all outcomes remain dry-run, never applied OS effects

@dataclass
class _Grant:
    principal: str
    session_id: str
    resource_id: str
    frame_epoch: int
    width: int
    height: int
    capability: str
    expires: float
    remaining: int

class PreviewGate:
    """Ephemeral, bounded, one-use preview grants bound to a full target tuple.

    `issue` must only be called by a trusted in-process human-approval harness.
    No network/IPC interface to issue exists. Identity is NOT OS authenticated here.
    """
    def __init__(self, clock=monotonic):
        self._clock = clock
        self._grants: dict[str, _Grant] = {}
        self._seen: set[str] = set()  # bounded, in-process, non-durable
        self._seen_order = deque()
        self._events = deque(maxlen=MAX_EVENTS)
        self._lock = RLock()
        self._last_now = None  # clock regressions invalidate all short-lived grants

    @property
    def event_count(self):
        with self._lock:
            return len(self._events)

    @property
    def grant_count(self):
        with self._lock:
            return len(self._grants)

    def issue(self, *, human_approved: bool, principal: str, session_id: str,
              resource_id: str, frame_epoch: int, width: int, height: int,
              ttl_seconds: float = 10.0) -> str:
        if human_approved is not True:
            raise GateError('APPROVAL_REQUIRED')
        if not all(_token(v) for v in (principal, session_id, resource_id)):
            raise GateError('INVALID_SCOPE')
        if type(frame_epoch) is not int or frame_epoch < 0:
            raise GateError('INVALID_EPOCH')
        if type(width) is not int or type(height) is not int or not (1 <= width <= 16384 and 1 <= height <= 16384):
            raise GateError('INVALID_DIMENSIONS')
        if type(ttl_seconds) not in (float, int) or not (0 < ttl_seconds <= MAX_TTL_SECONDS):
            raise GateError('INVALID_TTL')
        with self._lock:
            self._prune()
            if len(self._grants) >= MAX_GRANTS:
                raise GateError('GRANT_LIMIT')
            grant_id = str(uuid4())
            self._grants[grant_id] = _Grant(principal, session_id, resource_id,
                                            frame_epoch, width, height, CAPABILITY,
                                            self._last_now + ttl_seconds, 1)
            return grant_id

    def revoke(self, grant_id: str) -> bool:
        with self._lock:
            return self._grants.pop(grant_id, None) is not None

    def _prune(self):
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            self._grants.clear()
            raise GateError('CLOCK_ANOMALY')
        if self._last_now is not None and now < self._last_now:
            self._grants.clear()
            self._last_now = now
            raise GateError('CLOCK_ANOMALY')
        self._last_now = now
        for gid, grant in tuple(self._grants.items()):
            if now >= grant.expires:
                del self._grants[gid]

    @staticmethod
    def _valid_proposal(p):
        # Must not rely on Python's bool/int or float/int equality coercions.
        if type(p) is not PreviewProposal or not _uuid(p.request_id):
            return 'INVALID_REQUEST'
        if not all(_token(v) for v in (p.principal, p.session_id, p.resource_id)) or p.capability != CAPABILITY:
            return 'INVALID_SCOPE'
        if type(p.frame_epoch) is not int or p.frame_epoch < 0:
            return 'INVALID_EPOCH'
        if (type(p.width) is not int or type(p.height) is not int or
                not (1 <= p.width <= 16384 and 1 <= p.height <= 16384)):
            return 'INVALID_DIMENSIONS'
        if (type(p.x) is not int or type(p.y) is not int or
                not (0 <= p.x < p.width and 0 <= p.y < p.height)):
            return 'INVALID_COORDINATES'
        return None

    def check_and_consume(self, grant_id: str, proposal: PreviewProposal) -> GateResult:
        """Atomic check-and-consume. ALL successful results are `DRY_RUN_ONLY`."""
        with self._lock:
            try:
                self._prune()
            except GateError:
                return self._decision('CLOCK_ANOMALY', False)
            invalid = self._valid_proposal(proposal)
            if invalid:
                return self._decision(invalid, False)
            if proposal.request_id in self._seen:
                return self._decision('REPLAY_REJECTED', False)
            if not _uuid(grant_id):
                return self._decision('INVALID_GRANT', False)
            grant = self._grants.get(grant_id)
            if grant is None:
                return self._decision('NO_ACTIVE_GRANT', False)
            if ((proposal.principal, proposal.session_id, proposal.resource_id,
                 proposal.frame_epoch, proposal.width, proposal.height, proposal.capability) !=
                (grant.principal, grant.session_id, grant.resource_id,
                 grant.frame_epoch, grant.width, grant.height, grant.capability)):
                return self._decision('SCOPE_MISMATCH', False)
            # Consumed only on an allowed proposal, invalid attempts cannot steal grants.
            self._seen.add(proposal.request_id)
            self._seen_order.append(proposal.request_id)
            if len(self._seen_order) > MAX_SEEN:
                self._seen.discard(self._seen_order.popleft())
            self._grants.pop(grant_id)
            return self._decision('DRY_RUN_ONLY', True)

    def _decision(self, code, accepted):
        # no raw coordinates, tokens, principal or human-readable UI context in log
        self._events.append(code)
        return GateResult(code, accepted)
