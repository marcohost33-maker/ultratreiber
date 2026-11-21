"""W28 static gates (A7-R6 U6-3 and the assert form of U6-4).

U6-3: W27 found that a socket adopted with ``socket.socket(fileno=fd)``
inherits O_NONBLOCK from the shared open file description while Python reports
it as blocking. Every adoption in ``udx_ref/`` and ``tools/`` must therefore set
its own timeout (``settimeout``/``setblocking``) before any other use. The
audit found three adoptions (demo_w8, demo_w9, demo_w10), all compliant; this
gate keeps it that way. Descriptors received with SCM_RIGHTS are regular files
(``ApprovedFdReader`` requires S_ISREG), for which O_NONBLOCK has no effect,
and ``accept()`` on Linux does not inherit O_NONBLOCK; ``linux_ipc`` sets the
connection timeout explicitly anyway.

U6-4 (assert): ``python -O`` removes ``assert`` statements, so a refusal
written as an assert would silently disappear. The runtime package has none.
"""
import ast
import pathlib
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCANNED = sorted(list((REPO / 'udx_ref').glob('*.py')) + list((REPO / 'tools').glob('*.py')))
CONFIGURE = ('settimeout', 'setblocking')


def _is_adoption(call) -> bool:
    if not isinstance(call, ast.Call):
        return False
    name = ast.unparse(call.func)
    if name in ('socket.fromfd', 'socket.socket', 'socket'):
        return name == 'socket.fromfd' or any(k.arg == 'fileno' for k in call.keywords)
    return False


def unconfigured_adoptions(source: str, rel: str) -> list:
    """Adoptions whose first use of the adopted name is not settimeout/setblocking."""
    problems = []
    for node in ast.walk(ast.parse(source)):
        body = getattr(node, 'body', None)
        if not isinstance(body, list):
            continue
        for i, stmt in enumerate(body):
            if not (isinstance(stmt, ast.Assign) and _is_adoption(stmt.value)
                    and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):
                continue
            name = stmt.targets[0].id
            first = None
            for later in body[i + 1:]:
                for sub in ast.walk(later):
                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                            and sub.value.id == name and sub.attr != 'close':
                        first = sub.attr
                        break
                if first:
                    break
            if first not in CONFIGURE:
                problems.append(f'{rel}:{stmt.lineno} {name} first used as .{first}')
    return problems


class AdoptedSocketsSetTheirOwnTimeout(unittest.TestCase):
    def test_every_adoption_in_the_repository_configures_blocking_first(self):
        found, problems = 0, []
        for path in SCANNED:
            source = path.read_text(encoding='utf-8')
            rel = path.relative_to(REPO).as_posix()
            found += sum(1 for n in ast.walk(ast.parse(source)) if _is_adoption(n))
            problems += unconfigured_adoptions(source, rel)
        self.assertEqual(problems, [])
        self.assertEqual(found, 3)         # demo_w8, demo_w9, demo_w10; a new one must be looked at

    def test_the_gate_detects_an_unconfigured_adoption(self):
        bad = 'import socket\ndef f(fd):\n    s = socket.socket(fileno=fd)\n    s.recv(1)\n'
        self.assertEqual(unconfigured_adoptions(bad, 'x.py'), ['x.py:3 s first used as .recv'])
        bad2 = 'import socket\ndef f(fd):\n    s = socket.fromfd(fd, 1, 1)\n    return s\n'
        self.assertEqual(unconfigured_adoptions(bad2, 'x.py'), ['x.py:3 s first used as .None'])
        good = 'import socket\ndef f(fd):\n    s = socket.socket(fileno=fd)\n    try:\n        s.settimeout(2.0)\n        s.recv(1)\n    finally:\n        s.close()\n'
        self.assertEqual(unconfigured_adoptions(good, 'x.py'), [])


class NoAssertInTheRuntimePackage(unittest.TestCase):
    def test_no_assert_statement(self):
        hits = [f'{p.name}:{n.lineno}' for p in sorted((REPO / 'udx_ref').glob('*.py'))
                for n in ast.walk(ast.parse(p.read_bytes())) if isinstance(n, ast.Assert)]
        self.assertEqual(hits, [])


if __name__ == '__main__':
    unittest.main()
