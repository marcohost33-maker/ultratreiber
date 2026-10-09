"""W9 fail-closed FileChooser response parser -- NOT a live D-Bus portal client.

Must only be called by a trusted portal integration that authenticated the D-Bus
sender and tracked the request handle. Calling this from untrusted client data
would forge user consent. These checks cannot grant access on their own.
"""
from __future__ import annotations
from urllib.parse import urlsplit, unquote_to_bytes

class PortalRejected(ValueError):
    pass


def validate_chooser_result(response_code, results):
    """One URI, local file only, no writable flag; return opaque URI not path.

    Explicit distinction: rejection/cancel is not a grant; a URI is not an FD
    nor a proof of authority. Follow-up integration must use the OS portal
    scope and verified application identity before opening the object.
    """
    if type(response_code) is not int or response_code != 0:
        raise PortalRejected('NOT_APPROVED')
    if type(results) is not dict or set(results) - {'uris', 'writable', 'choices', 'current_filter'}:
        raise PortalRejected('INVALID_PORTAL_RESPONSE')
    if results.get('writable', False) is not False:
        raise PortalRejected('WRITABLE_NOT_ALLOWED')
    uris = results.get('uris')
    if type(uris) is not list or len(uris) != 1 or type(uris[0]) is not str or len(uris[0]) > 8192:
        raise PortalRejected('EXACTLY_ONE_URI_REQUIRED')
    uri = uris[0]
    if '\x00' in uri or '\\' in uri:
        raise PortalRejected('INVALID_URI')
    try:
        parsed = urlsplit(uri)
        decoded = unquote_to_bytes(parsed.path)
    except (ValueError, UnicodeError):
        raise PortalRejected('INVALID_URI') from None
    if (parsed.scheme != 'file' or parsed.netloc not in ('', 'localhost') or
        parsed.query or parsed.fragment or not decoded.startswith(b'/') or
        b'\x00' in decoded or b'\\' in decoded or any(seg in (b'.', b'..') for seg in decoded.split(b'/'))):
        raise PortalRejected('NONLOCAL_OR_UNSAFE_URI')
    return uri
