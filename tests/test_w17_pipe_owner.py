"""W17 (issue #2): the pipe OWNER is the server user, whatever the token's default owner.

Root cause of issue #2: without ``O:`` in the SDDL the kernel assigns the
token's default owner (TokenOwner). For an elevated administrator that is
BUILTIN\\Administrators (S-1-5-32-544), not the user, so ``client_ping`` refused
the pipe before its first write (PIPE_OWNER_MISMATCH) and the server saw a broken
pipe (READ_FAILED). Cygwin/MSYS2 (Git Bash) sets TokenOwner to the user SID for
the processes it starts, which is why the bash-run suite job stayed green while
the pwsh-run collector failed on the hosted runner.

The discriminating test runs in a child process (the test runner's own token is
never changed): it switches the child's TokenOwner to an owner-capable group,
reads it back, reproduces the old failure with the pre-W17 SDDL as a control and
then shows the W17 server is owned by the user and completes the handshake.
On a standard (non-elevated) account no group carries SE_GROUP_OWNER, so the
child cannot move the default owner and the test SKIPS (reported, not green).
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import unittest
import uuid

from udx_ref import windows_pipe as wp

REPO = pathlib.Path(__file__).resolve().parents[1]
IS_WINDOWS = sys.platform == 'win32'

PRE_W17_SDDL = 'D:P(A;;GRGW;;;SY)(A;;GRGW;;;{sid})S:(ML;;NWNR;;;ME)'

# Child: move TokenOwner, prove it moved, then control (pre-W17 SDDL) and fix.
_CHILD = r'''
import ctypes, json, sys, threading
from ctypes import wintypes
from udx_ref import windows_pipe as wp

TokenGroups, TokenOwner = 2, 4
SE_GROUP_OWNER, SE_GROUP_USE_FOR_DENY_ONLY = 0x8, 0x10
api = wp.default_api()
out = {}
user = wp.current_user_sid(api)
out['user'] = user

tok = wintypes.HANDLE()
if not api.OpenProcessToken(api.GetCurrentProcess(), wp.TOKEN_QUERY | wp.TOKEN_ADJUST_DEFAULT,
                            ctypes.byref(tok)):
    print(json.dumps({'error': 'OPEN_PROCESS_TOKEN', 'winerror': api.last_error()})); sys.exit(0)

def owner_text():
    buf, err = wp._token_info(api, tok, TokenOwner)
    if buf is None:
        return None
    return wp.sid_to_text(api, ctypes.c_void_p.from_buffer(buf, 0).value)

out['default_owner_before'] = owner_text()
buf, err = wp._token_info(api, tok, TokenGroups)
if buf is None:
    print(json.dumps({'error': 'TOKEN_GROUPS', 'winerror': err})); sys.exit(0)
count = ctypes.c_uint32.from_buffer(buf, 0).value
ptr = ctypes.sizeof(ctypes.c_void_p)
candidate = None
for i in range(count):
    off = ptr + i * 2 * ptr          # TOKEN_GROUPS: DWORD count padded to pointer, then SID_AND_ATTRIBUTES
    sid = ctypes.c_void_p.from_buffer(buf, off).value
    attrs = ctypes.c_uint32.from_buffer(buf, off + ptr).value
    if attrs & SE_GROUP_OWNER and not attrs & SE_GROUP_USE_FOR_DENY_ONLY:
        text = wp.sid_to_text(api, sid)
        if text != user:
            candidate = (sid, text)
            break
if candidate is None:
    print(json.dumps({'skip': 'NO_OWNER_CAPABLE_GROUP', **out})); sys.exit(0)

owner = ctypes.c_void_p(candidate[0])
if not api.SetTokenInformation(tok, TokenOwner, ctypes.byref(owner), ctypes.sizeof(owner)):
    print(json.dumps({'error': 'SET_TOKEN_OWNER', 'winerror': api.last_error(), **out})); sys.exit(0)
out['group'] = candidate[1]
out['default_owner_after'] = owner_text()       # readback: the mutation took effect

def run(name):
    with wp.OneShotPipeServer(name) as srv:
        o, sd, rc = wp.pipe_owner_sid(api, srv.handle)
        try:
            pipe_owner = wp.sid_to_text(api, o) if o is not None else None
        finally:
            if sd is not None and sd.value:
                api.LocalFree(sd)
        res = {}
        t = threading.Thread(target=lambda: res.update(c=wp.client_ping(name)), daemon=True)
        t.start()
        r = srv.serve(10.0)
        t.join(10)
    c = res.get('c')
    return {'pipe_owner': pipe_owner, 'server': [r.verdict, r.reason],
            'client': None if c is None else [c.reason, c.sent]}

name = sys.argv[1]
real_build = wp.build_sddl
wp.build_sddl = lambda sid: ''' + repr(PRE_W17_SDDL) + r'''.format(sid=wp.validate_sid_text(sid))
try:
    out['control'] = run(name + '_control')
finally:
    wp.build_sddl = real_build
out['fixed'] = run(name + '_fixed')
api.CloseHandle(tok)
print(json.dumps(out))
'''


class PortableOwnerSddl(unittest.TestCase):
    def test_owner_is_explicit_server_user(self):
        sid = 'S-1-5-21-1-2-3-1001'
        sddl = wp.build_sddl(sid)
        self.assertTrue(sddl.startswith('O:' + sid + 'D:P('))
        self.assertEqual(sddl.count('O:'), 1)
        self.assertNotIn('G:', sddl)                      # primary group stays defaulted

    def test_cpp_candidate_sets_the_same_owner(self):
        cpp = (REPO / 'windows' / 'udx_sid_probe.cpp').read_text()
        self.assertLess(cpp.index('L"O:"'), cpp.index('L"D:P(A;;GRGW;;;SY)(A;;GRGW;;;"'))


@unittest.skipUnless(IS_WINDOWS, 'Windows runtime required')
class WindowsPipeOwner(unittest.TestCase):
    def test_live_pipe_owner_equals_server_user(self):
        api = wp.default_api()
        with wp.OneShotPipeServer(wp.PIPE_PREFIX + 'UDX_W17_' + uuid.uuid4().hex) as srv:
            o, sd, rc = wp.pipe_owner_sid(api, srv.handle)
            self.assertEqual(rc, 0)
            try:
                self.assertEqual(wp.sid_to_text(api, o), srv.server_sid)
            finally:
                api.LocalFree(sd)

    def test_moved_default_owner_reproduces_issue_2_and_w17_fixes_it(self):
        env = dict(os.environ, PYTHONPATH=str(REPO))
        name = wp.PIPE_PREFIX + 'UDX_W17_' + uuid.uuid4().hex
        proc = subprocess.run([sys.executable, '-I', '-c', 'import sys; sys.path.insert(0, %r)\n' % str(REPO)
                               + _CHILD, name],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        if 'skip' in out:
            self.skipTest('%s (default owner %s): needs an elevated administrator token'
                          % (out['skip'], out.get('default_owner_before')))
        self.assertNotIn('error', out, out)
        # Infection: the child's default owner really is the group now.
        self.assertEqual(out['default_owner_after'], out['group'])
        self.assertNotEqual(out['group'], out['user'])
        # Control (pre-W17 SDDL): exactly the issue #2 failure.
        self.assertEqual(out['control']['pipe_owner'], out['group'])
        self.assertEqual(out['control']['client'], ['PIPE_OWNER_MISMATCH', False])
        # Server side as in issue #2 (READ_FAILED); CONNECT_FAILED if the client
        # already closed before ConnectNamedPipe (same set as the W12 owner test).
        self.assertEqual(out['control']['server'][0], 'DENIED')
        self.assertIn(out['control']['server'][1], ('READ_FAILED', 'CONNECT_FAILED'))
        # W17: owned by the user despite the moved default, handshake completes.
        self.assertEqual(out['fixed']['pipe_owner'], out['user'])
        self.assertEqual(out['fixed']['client'], ['OK', True])
        self.assertEqual(out['fixed']['server'], ['PEER_OK', 'OK'])


if __name__ == '__main__':
    unittest.main()
