"""UDX standalone-first read-only protocol reference; NOT a real OS driver.

Production MUST bind peer identity to authenticated OS IPC (not payload fields).
No local filesystem, subprocess or networking capability is implemented.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections import OrderedDict, deque
from threading import RLock
from types import MappingProxyType
import json
import re
import uuid

VERSION = 'udx/0.1'
MAX_MESSAGE_BYTES = 4096
MAX_SEEN = 1024
MAX_AUDIT = 256
MAX_SAFE_JSON_INTEGER = 9007199254740991
MAX_NESTING = 16
_ACTION = re.compile(r'[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+\Z', re.ASCII)
_OBJECT = re.compile(r'[a-z][a-z0-9-]{0,63}\Z', re.ASCII)
_FIELDS = {'version', 'request_id', 'capability', 'params'}

class Refusal(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def unique_pairs(pairs):
    out = {}
    for key, val in pairs:
        if key in out:
            raise Refusal('DUPLICATE_JSON_KEY')
        out[key] = val
    return out

def reject_int(s):
    # I-JSON safe integer range, shared with JS Number's exact integer range.
    # This is a wire-level constraint, not a general-purpose JSON Schema rule.
    n = int(s)
    if abs(n) > MAX_SAFE_JSON_INTEGER:
        raise Refusal('NON_INTEROPERABLE_JSON_NUMBER')
    return n


def check_scalars_and_depth(node, depth=0):
    if depth > MAX_NESTING:
        raise Refusal('NESTING_LIMIT')
    if type(node) is str:
        if any((0xd800 <= ord(c) <= 0xdfff) or
               (0xfdd0 <= ord(c) <= 0xfdef) or
               ((ord(c) & 0xffff) in (0xfffe, 0xffff)) for c in node):
            # RFC 7493: I-JSON forbids surrogates and Unicode noncharacters.
            raise Refusal('MALFORMED_JSON')
    elif type(node) is dict:
        for k,v in node.items():
            check_scalars_and_depth(k, depth+1)
            check_scalars_and_depth(v, depth+1)
    elif type(node) is list:
        for v in node:
            check_scalars_and_depth(v, depth+1)


def reject_float(_):
    raise Refusal('NON_INTEGER_JSON_NUMBER')

def reject_constant(_):
    raise Refusal('NON_FINITE_JSON_NUMBER')

def decode_request(raw):
    if type(raw) is not bytes:
        raise Refusal('INVALID_FRAME')
    if len(raw) > MAX_MESSAGE_BYTES:
        raise Refusal('FRAME_TOO_LARGE')
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique_pairs,
                         parse_float=reject_float, parse_int=reject_int,
                         parse_constant=reject_constant)
    except Refusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise Refusal('MALFORMED_JSON') from None
    check_scalars_and_depth(obj)
    if type(obj) is not dict or set(obj) != _FIELDS:
        raise Refusal('INVALID_ENVELOPE')
    if obj['version'] != VERSION:
        raise Refusal('UNSUPPORTED_VERSION')
    rid = obj['request_id']
    if type(rid) is not str:
        raise Refusal('INVALID_REQUEST_ID')
    try:
        if str(uuid.UUID(rid)) != rid or len(rid) != 36:
            raise ValueError('non-canonical')
    except ValueError:
        raise Refusal('INVALID_REQUEST_ID') from None
    cap = obj['capability']
    if type(cap) is not str or len(cap) > 72 or not _ACTION.fullmatch(cap):
        raise Refusal('INVALID_CAPABILITY')
    if type(obj['params']) is not dict:
        raise Refusal('INVALID_PARAMS')
    return obj

@dataclass(frozen=True)
class PeerIdentity:
    subject: str
    authenticated: bool

@dataclass(frozen=True)
class ObjectMetadata:
    object_id: str
    owner: str
    size_bytes: int
    kind: str

class FixtureAdapter:
    """Fixed in-memory objects; never reads the actual filesystem."""
    def __init__(self, objects):
        self.objects = dict(objects)
        self.read_count = 0

    def read_metadata(self, oid, subject):
        item = self.objects.get(oid)
        if item is None or item.owner != subject:
            raise Refusal('OBJECT_ACCESS_DENIED')
        self.read_count += 1
        return {'object_id': item.object_id, 'kind': item.kind, 'size_bytes': item.size_bytes}

class Policy:
    def __init__(self, grants):
        self.grants = {key: frozenset(v) for key, v in grants.items()}

    def allows(self, subject, grant):
        return grant in self.grants.get(subject, frozenset())

    def replace_grants(self, subject, grants):
        """Prototype-only operator API. NOT production policy management."""
        self.grants[subject] = frozenset(grants)

# Explicit, closed action catalog. Discovery reveals support, not permission.
CAPABILITIES = MappingProxyType({
    'device.capabilities.list': ('udx.discover', 'list'),
    'object.metadata.read': ('udx.metadata.read', 'metadata'),
})

class Broker:
    """Synchronous read-only reference dispatcher, not OS broker or IPC service."""
    def __init__(self, adapter, policy):
        self.adapter, self.policy = adapter, policy
        self.seen = OrderedDict()  # Process-local only; NOT durable replay protection.
        self.audit = deque(maxlen=MAX_AUDIT)  # Bounded in-memory diagnostics, NOT durable evidence.
        self._lock = RLock()      # Atomic replay check+decision+audit under concurrent IPC.

    def handle(self, raw, peer):
        with self._lock:
            return self._handle_locked(raw, peer)

    def _handle_locked(self, raw, peer):
        rid = None
        try:
            req = decode_request(raw)
            rid = req['request_id']
            if (type(peer) is not PeerIdentity or type(peer.authenticated) is not bool
                    or peer.authenticated is not True or type(peer.subject) is not str
                    or not peer.subject):
                raise Refusal('UNAUTHENTICATED_PEER')
            key = (peer.subject, rid)
            if key in self.seen:
                raise Refusal('REPLAY_REJECTED')
            self.seen[key] = None
            if len(self.seen) > MAX_SEEN:
                self.seen.popitem(last=False)
            cap = req['capability']
            if cap not in CAPABILITIES:
                raise Refusal('UNKNOWN_CAPABILITY')
            grant, operation = CAPABILITIES[cap]
            if not self.policy.allows(peer.subject, grant):
                raise Refusal('CAPABILITY_NOT_GRANTED')
            params = req['params']
            if operation == 'list':
                if params != {}:
                    raise Refusal('INVALID_PARAMS')
                data = {'capabilities': [{'name': name, 'effect': 'read',
                        'supported_by_reference': True} for name in sorted(CAPABILITIES)]}
            elif operation == 'metadata':
                if set(params) != {'object_id'}:
                    raise Refusal('INVALID_PARAMS')
                oid = params['object_id']
                if type(oid) is not str or not _OBJECT.fullmatch(oid):
                    raise Refusal('INVALID_OBJECT_ID')
                data = self.adapter.read_metadata(oid, peer.subject)
            else:
                raise Refusal('UNKNOWN_CAPABILITY')
            code = 'OK'
        except Refusal as exc:
            code, data = exc.code, None
        except Exception:
            # Do not leak secrets or tracebacks; production must quarantine on uncertain effects.
            code, data = 'INTERNAL_ERROR', None
        self.audit.append({'request_id': rid, 'code': code})
        return {'version': VERSION, 'request_id': rid, 'status': 'OK' if code == 'OK' else 'DENIED',
                'code': code, 'data': data}


def decode_response(raw, expected_request_id=None, expected_capability=None, expected_params=None):
    """Strict client response contract (not server authentication).

    On successful request parsing, the echoed request ID must match; for a
    rejected malformed request it may be null. This is a supplementary
    invariant; an attacker controlling the same UID can still impersonate a
    service and return arbitrary well-formed data.
    """
    if type(raw) is not bytes:
        raise Refusal('INVALID_RESPONSE')
    if len(raw) > MAX_MESSAGE_BYTES:
        raise Refusal('FRAME_TOO_LARGE')
    try:
        result = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique_pairs,
                            parse_float=reject_float, parse_int=reject_int,
                            parse_constant=reject_constant)
        check_scalars_and_depth(result)
    except Refusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise Refusal('INVALID_RESPONSE') from None
    if type(result) is not dict or set(result) != {'version','request_id','status','code','data'}:
        raise Refusal('INVALID_RESPONSE')
    if result['version'] != VERSION:
        raise Refusal('INVALID_RESPONSE')
    rid = result['request_id']
    if rid is not None:
        if type(rid) is not str:
            raise Refusal('INVALID_RESPONSE')
        try:
            if str(uuid.UUID(rid)) != rid or len(rid) != 36:
                raise ValueError('noncanonical ID')
        except ValueError:
            raise Refusal('INVALID_RESPONSE') from None
    if expected_request_id is not None and rid != expected_request_id:
        raise Refusal('REQUEST_ID_MISMATCH')
    status = result['status']; code = result['code']; data = result['data']
    if type(code) is not str or re.fullmatch(r'[A-Z][A-Z_]*',code) is None:
        raise Refusal('INVALID_RESPONSE')
    if status == 'OK':
        if code != 'OK' or type(data) is not dict or rid is None:
            raise Refusal('INVALID_RESPONSE')
    elif status == 'DENIED':
        if code == 'OK' or data is not None:
            raise Refusal('INVALID_RESPONSE')
    else:
        raise Refusal('INVALID_RESPONSE')
    if status == 'OK' and expected_capability is not None:
        # Shape authorization is deliberately coupled to the *requested*
        # capability; a generic successful object is not automatically safe.
        if expected_capability == 'object.metadata.read':
            if set(data) != {'object_id','kind','size_bytes'}:
                raise Refusal('INVALID_RESPONSE_DATA')
            if (type(data['object_id']) is not str or not _OBJECT.fullmatch(data['object_id']) or
                type(data['kind']) is not str or not _OBJECT.fullmatch(data['kind']) or
                type(data['size_bytes']) is not int or not (0 <= data['size_bytes'] <= MAX_SAFE_JSON_INTEGER)):
                raise Refusal('INVALID_RESPONSE_DATA')
            if expected_params is not None and data['object_id'] != expected_params.get('object_id'):
                raise Refusal('RESPONSE_OBJECT_MISMATCH')
        elif expected_capability == 'device.capabilities.list':
            if set(data) != {'capabilities'} or type(data['capabilities']) is not list:
                raise Refusal('INVALID_RESPONSE_DATA')
            names = set()
            for item in data['capabilities']:
                if (type(item) is not dict or set(item) != {'name','effect','supported_by_reference'} or
                    type(item['name']) is not str or item['name'] not in CAPABILITIES or
                    item['effect'] != 'read' or item['supported_by_reference'] is not True or
                    item['name'] in names):
                    raise Refusal('INVALID_RESPONSE_DATA')
                names.add(item['name'])
        else:
            raise Refusal('INVALID_RESPONSE_DATA')
    return result
