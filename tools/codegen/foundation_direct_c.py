from __future__ import annotations

"""Compatibility stub for the former foundation-specific direct C adapter.

Foundation enum rendering now comes from the shared IR-driven enum renderer in
`project_c_backend.py` via `project_direct_registry.py`.
"""

from pathlib import Path



def direct_c_renderers(repo_root: str | Path = ".") -> dict[str, object]:
    del repo_root
    return {}
