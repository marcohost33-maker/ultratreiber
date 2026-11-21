"""W28: E2 witnesses for the W27 EQUIVALENT pins (A7-R6 U6-1) and UDX28-02.

W27 pinned four ADMIT survivors as EQUIVALENT (no input reaches the refusal).
Cross-family review (A7-R15/R16) called the reasons plausible at E1 but asked
for adversarial runs, "especially float deadline addition against extreme
values". The runs below are those witnesses. One pin did not hold:

* UDX28-02: ``PortalRequest`` accepted any ``int`` clock value. For an int
  beyond the float range ``math.isfinite`` raises OverflowError, so the clock
  check crashed untyped; for ``now = 2**1024 - 2**970 - 1`` the clock check
  passes (it rounds to the largest float) but ``now + 300`` does not, so the
  "unreachable" deadline refusal *is* reachable - and crashed untyped before
  W28. The same class was in ``PreviewGate`` (10**400 -> OverflowError) and
  ``DurableGrantStore`` (a nanosecond clock beyond the signed 64-bit SQLite
  INTEGER -> OverflowError). All three now refuse typed.

The three remaining EQUIVALENT pins get witnesses that exercise their
boundaries: the handoff envelopes have one fixed length for every accepted
argument, and a file that grows past the limit after admission is refused as
RESOURCE_CHANGED before the size check is reached.
"""
from __future__ import annotations

import json
import math
import os
import pathlib
import random
import struct
import sys
import tempfile
import unittest
import uuid

from udx_ref import fd_handoff, fd_reader
from udx_ref.portal_request import PortalFlowError, PortalRequest
from udx_ref.preview_gate import GateError, PreviewGate

FLOAT_EDGE = 2**1024 - 2**970        # smallest int that float() rounds to infinity
SEED = 20261121


def _portal(now):
    return PortalRequest(caller_unique=':1.2', portal_owner_unique=':1.3', ttl_seconds=300,
                         clock=lambda: now)


def _clock_corpus():
    """Deterministic extreme and random clock values (int and float)."""
    rnd = random.Random(SEED)
    values = [0, 0.0, -0.0, 1, 5e-324, sys.float_info.max, -sys.float_info.max,
              int(sys.float_info.max), FLOAT_EDGE - 301, FLOAT_EDGE - 300, FLOAT_EDGE - 1, FLOAT_EDGE,
              10**308, 10**400, -10**400, 2**63, 2**64, math.inf, -math.inf, math.nan, True, False]
    for k in range(0, 1100, 7):
        values += [2**k - 1, 2**k, 2**k + 1]
    for _ in range(2000):
        values.append(struct.unpack('<d', rnd.getrandbits(64).to_bytes(8, 'little'))[0])
    return values


class PortalClockExtremes(unittest.TestCase):
    """Witness for ADMIT ...portal_request.py|PortalRequest.__init__|PortalFlowError:BAD_CLOCK."""

    def test_int_beyond_float_range_is_bad_clock_not_overflow(self):
        for now in (10**400, FLOAT_EDGE, 2**2000):
            with self.subTest(now=now), self.assertRaisesRegex(PortalFlowError, '^BAD_CLOCK$'):
                _portal(now)

    def test_deadline_overflow_is_reachable_and_refused(self):
        # The clock check passes: the value rounds to the largest float.
        self.assertEqual(float(FLOAT_EDGE - 1), sys.float_info.max)
        with self.assertRaises(OverflowError):
            float(FLOAT_EDGE - 1 + 300)
        with self.assertRaisesRegex(PortalFlowError, '^BAD_CLOCK$'):
            _portal(FLOAT_EDGE - 1)

    def test_positive_controls_at_the_edge(self):
        self.assertEqual(_portal(FLOAT_EDGE - 301).state, 'AWAITING_REPLY')
        self.assertEqual(_portal(sys.float_info.max).state, 'AWAITING_REPLY')   # max + 300.0 == max
        self.assertEqual(_portal(0).state, 'AWAITING_REPLY')

    def test_property_every_clock_value_is_accepted_finite_or_refused_typed(self):
        accepted = refused = 0
        for now in _clock_corpus():
            try:
                request = _portal(now)
            except PortalFlowError as exc:
                self.assertIn(str(exc), ('BAD_CLOCK',), repr(now))
                refused += 1
            else:
                self.assertTrue(math.isfinite(float(request._deadline)), repr(now))
                self.assertGreaterEqual(now, 0)
                accepted += 1
        self.assertGreater(accepted, 100)
        self.assertGreater(refused, 100)


class PreviewGateClockExtremes(unittest.TestCase):
    def _issue(self, now):
        gate = PreviewGate(clock=lambda: now)
        return gate.issue(human_approved=True, principal='p', session_id='s', resource_id='r',
                          frame_epoch=1, width=2, height=2)

    def test_int_beyond_float_range_is_clock_anomaly_not_overflow(self):
        for now in (10**400, FLOAT_EDGE):
            with self.subTest(now=now), self.assertRaisesRegex(GateError, '^CLOCK_ANOMALY$'):
                self._issue(now)
        self.assertTrue(self._issue(int(sys.float_info.max)))                  # positive control

    def test_property_every_clock_value_issues_or_refuses_typed(self):
        for now in _clock_corpus():
            try:
                self._issue(now)
            except GateError as exc:
                self.assertEqual(str(exc), 'CLOCK_ANOMALY', repr(now))


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid'), 'POSIX store checks required')
class DurableClockRange(unittest.TestCase):
    def setUp(self):
        from udx_ref import durable_grants
        self.d = durable_grants
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w28-')
        self.path = pathlib.Path(self.dir.name) / 'src'
        self.path.write_bytes(b'w28')

    def tearDown(self):
        self.dir.cleanup()

    def _issue(self, now, name):
        store = self.d.DurableGrantStore(str(pathlib.Path(self.dir.name) / name), clock_ns=lambda: now)
        fd = os.open(self.path, os.O_RDONLY)
        try:
            return store.issue(fd, issuer_uid=os.getuid(), recipient_uid=os.getuid() + 1, ttl_seconds=300)
        finally:
            os.close(fd)
            store.close()

    def test_largest_clock_with_longest_ttl_fits_sqlite(self):
        self.assertEqual(self.d.MAX_CLOCK_NS + 300 * 10**9, 2**63 - 1)
        self.assertTrue(self._issue(self.d.MAX_CLOCK_NS, 'edge.db'))

    def test_beyond_is_invalid_clock_not_overflow(self):
        for i, now in enumerate((self.d.MAX_CLOCK_NS + 1, 2**63, 10**400)):
            with self.subTest(now=now), self.assertRaisesRegex(self.d.GrantDenied, '^INVALID_CLOCK$'):
                self._issue(now, f'b{i}.db')


class EnvelopeLengthIsFixed(unittest.TestCase):
    """Witness for the two SIZE_LIMIT pins of send_approved_fd / send_readonly_request.

    Only a canonical 36-character UUID passes the argument check, and UUID
    characters need no JSON escaping; protocol tag and operation are
    constants. So the envelope has one length for every accepted argument.
    """

    @staticmethod
    def envelope(rid):
        return json.dumps({'v': fd_handoff.PROTOCOL, 'op': fd_handoff.OPERATION, 'id': rid},
                          sort_keys=True, separators=(',', ':')).encode('ascii')

    def test_every_canonical_uuid_gives_the_same_length_far_below_max_wire(self):
        rnd = random.Random(SEED)
        ids = ['00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff']
        ids += [str(uuid.UUID(int=rnd.getrandbits(128))) for _ in range(5000)]
        lengths = {len(self.envelope(i)) for i in ids if fd_handoff._canonical_uuid(i)}
        self.assertEqual(len(lengths), 1)
        self.assertLess(lengths.pop(), fd_handoff.MAX_WIRE // 2)

    def test_long_or_escaping_ids_never_reach_the_size_check(self):
        for bad in ('a' * 10_000, '"' * 36, 'é' * 36, str(uuid.uuid4()).upper(), str(uuid.uuid4()) + ' '):
            with self.subTest(bad=bad[:8]):
                self.assertFalse(fd_handoff._canonical_uuid(bad))
                with self.assertRaisesRegex(fd_handoff.HandoffError, '^BAD_ARGUMENT$'):
                    fd_handoff.send_approved_fd(None, 0, bad)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'pread'), 'POSIX pread required')
class GrowthAfterAdmission(unittest.TestCase):
    """Witness for ADMIT ...fd_reader.py|ApprovedFdReader.read|ReadGuardError:SIZE_LIMIT|6c649be96220."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w28-')
        self.path = pathlib.Path(self.dir.name) / 'grow'

    def tearDown(self):
        self.dir.cleanup()

    def test_growth_past_the_limit_is_resource_changed_before_the_size_check(self):
        self.path.write_bytes(b'x' * 16)
        fd = os.open(self.path, os.O_RDONLY)
        try:
            with fd_reader.ApprovedFdReader(fd, limit=16) as reader:
                self.assertEqual(reader.read(), b'x' * 16)                    # exactly the limit: admitted
                with open(self.path, 'ab') as f:
                    f.write(b'y' * 64)
                with self.assertRaisesRegex(fd_reader.ReadGuardError, '^RESOURCE_CHANGED$'):
                    reader.read()
        finally:
            os.close(fd)

    def test_above_the_limit_at_admission_is_size_limit(self):
        self.path.write_bytes(b'x' * 17)
        fd = os.open(self.path, os.O_RDONLY)
        try:
            with self.assertRaisesRegex(fd_reader.ReadGuardError, '^SIZE_LIMIT$'):
                fd_reader.ApprovedFdReader(fd, limit=16)
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
