"""RAII-inspired mock GPU lease, to model ReleaseFrame ownership.
NOT a DXGI binding. Prevents access after release in this Python fixture.
"""
from contextlib import contextmanager

class ReleasedFrame(RuntimeError):
    pass

class FrameLease:
    def __init__(self, handle):
        self._handle = handle
        self._active = True

    @property
    def handle(self):
        if not self._active:
            raise ReleasedFrame('frame already released')
        return self._handle

    def _invalidate(self):
        self._active = False
        self._handle = None

@contextmanager
def frame_lease(acquire, release):
    handle = acquire()
    lease = FrameLease(handle)
    try:
        yield lease
    finally:
        lease._invalidate()
        release()
