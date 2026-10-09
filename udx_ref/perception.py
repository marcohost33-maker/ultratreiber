"""Data-minimizing, bounded tile-change signal. Does NOT capture or save images.

Reports changed *tile fraction* (not changed pixel fraction), and stable-state
heuristics; not a semantic UI validator, OCR engine, consent mechanism, or GPU
zero-copy claim. Previous complete frames are never retained by this object.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import blake2b
from secrets import token_bytes
from threading import RLock

MAX_FRAME_BYTES = 16 * 1024 * 1024
MAX_TILES = 4096

@dataclass(frozen=True)
class FrameSignal:
    state: str
    changed_tile_fraction: float | None
    stable_observations: int
    tile_count: int

class TileChangeTracker:
    def __init__(self, *, tile_edge=64, quiet_observations=3, change_threshold=0.005):
        if type(tile_edge) is not int or not 8 <= tile_edge <= 512:
            raise ValueError('bad tile_edge')
        if type(quiet_observations) is not int or not 1 <= quiet_observations <= 120:
            raise ValueError('bad quiet_observations')
        if type(change_threshold) not in (int, float) or not (0 <= change_threshold <= 1):
            raise ValueError('bad change_threshold')
        self.tile_edge = tile_edge
        self.quiet_observations = quiet_observations
        self.threshold = change_threshold
        self._lock = RLock()
        self._key = token_bytes(32)  # per-instance secret; rotate at reset
        self._meta = None
        self._hashes = None
        self._quiet = 0

    def reset(self):
        with self._lock:
            self._meta, self._hashes, self._quiet = None, None, 0
            self._key = token_bytes(32)

    def inspect(self, frame: bytes, *, width: int, height: int, channels: int = 4) -> FrameSignal:
        with self._lock:
            return self._inspect_locked(frame, width=width, height=height, channels=channels)

    def _inspect_locked(self, frame: bytes, *, width: int, height: int, channels: int = 4) -> FrameSignal:
        if type(width) is not int or type(height) is not int or type(channels) is not int:
            raise ValueError('dimensions must be integers')
        if not (1 <= width <= 8192 and 1 <= height <= 8192 and channels in (1, 3, 4)):
            raise ValueError('invalid dimensions')
        expected = width * height * channels
        if expected > MAX_FRAME_BYTES or type(frame) is not bytes or len(frame) != expected:
            raise ValueError('frame exceeds budget or incorrect frame size')
        edge = self.tile_edge
        nx = (width + edge - 1) // edge
        ny = (height + edge - 1) // edge
        if nx * ny > MAX_TILES:
            raise ValueError('too many tiles')
        pitch = width * channels
        digests = []
        mem = memoryview(frame)
        for ty in range(ny):
            h = min(edge, height - ty * edge)
            for tx in range(nx):
                x = tx * edge * channels
                chunk = min(edge, width - tx * edge) * channels
                digest = blake2b(digest_size=16, key=self._key, person=b'UDX-Tile-v1')
                for r in range(h):
                    start = (ty * edge + r) * pitch + x
                    digest.update(mem[start:start+chunk])
                digests.append(digest.digest())
        new_meta = (width, height, channels, edge)
        old = self._hashes if self._meta == new_meta else None
        self._meta, self._hashes = new_meta, tuple(digests)
        if old is None:
            self._quiet = 0
            return FrameSignal('BASELINE_REQUIRED', None, 0, len(digests))
        changed = sum(a != b for a, b in zip(old, digests))
        ratio = changed / len(digests)
        if changed == 0:
            self._quiet += 1
            state = ('STABLE_HEURISTIC' if self._quiet >= self.quiet_observations
                     else 'QUIET_CANDIDATE')
        else:
            self._quiet = 0
            state = 'LOW_CHANGE' if ratio <= self.threshold else 'CHANGING'
        return FrameSignal(state, ratio, self._quiet, len(digests))
