from __future__ import annotations

"""Shared registry for project-specific direct C renderer adapters.

Entity discovery is fully automatic — the IR is walked to find all enums,
modules, and classes.  Per-project *custom overrides* (e.g. special buffer
rendering for ``common``) are merged on top so that entities with bespoke
renderers still work.
"""

from collections.abc import Callable
from pathlib import Path
from typing import cast

from tools.codegen.project_c_backend import (
    DirectCRenderer,
    discover_renderers,
)
from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source


CustomOverrideFactory = Callable[[str | Path], dict[str, DirectCRenderer]]



def _common_custom_overrides(repo_root: str | Path = ".") -> dict[str, DirectCRenderer]:
    from tools.codegen.common_direct_c import custom_renderer_overrides

    return custom_renderer_overrides(repo_root)



def _noop_overrides(repo_root: str | Path = ".") -> dict[str, DirectCRenderer]:
    del repo_root
    return {}


_PROJECT_CUSTOM_OVERRIDES: dict[str, CustomOverrideFactory] = {
    "common": _common_custom_overrides,
    "foundation": _noop_overrides,
}



def supported_projects() -> tuple[str, ...]:
    return tuple(sorted(_PROJECT_CUSTOM_OVERRIDES))



def direct_c_renderers_for_project(
    project: str,
    repo_root: str | Path = ".",
    *,
    entity_kinds: set[str] | None = None,
) -> dict[str, object]:
    """Build the complete renderer map for *project* via IR auto-discovery.

    Parameters
    ----------
    project:
        Project name (e.g. ``"common"``, ``"foundation"``).
    repo_root:
        Repository root path used to locate XML models.
    entity_kinds:
        Optional filter forwarded to :func:`discover_renderers`.
    """
    if project not in _PROJECT_CUSTOM_OVERRIDES:
        raise ValueError(
            f"unsupported project '{project}'; expected one of: {', '.join(supported_projects())}"
        )

    project_ir = project_to_ir(load_named_project_source(project, repo_root))
    custom_overrides = _PROJECT_CUSTOM_OVERRIDES[project](repo_root)

    return discover_renderers(
        project_ir,
        entity_kinds=entity_kinds,
        custom_overrides=custom_overrides,
    )
