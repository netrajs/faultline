"""Shared pytest bootstrap.

``backend`` is not an installed package, so ``core``, ``generator`` and
``oracle`` are only importable when ``backend/`` itself is on ``sys.path``.
This file exists to put it there -- it is picked up automatically for every
test under this directory, regardless of which subdirectory pytest is
pointed at.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))
