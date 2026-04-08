from __future__ import annotations

"""Shared registry for project-specific direct C renderer adapters."""

from collections.abc import Callable
from pathlib import Path


DirectRendererFactory = Callable[[str | Path], dict[str, object]]



def _common_renderers(repo_root: str | Path = ".") -> dict[str, object]:
    from tools.codegen.common_direct_c import direct_c_renderers

    return direct_c_renderers(repo_root)



def _foundation_renderers(repo_root: str | Path = ".") -> dict[str, object]:
    from tools.codegen.foundation_direct_c import direct_c_renderers

    return direct_c_renderers(repo_root)


_PROJECT_DIRECT_RENDERERS: dict[str, DirectRendererFactory] = {
    "common": _common_renderers,
    "foundation": _foundation_renderers,
}



def supported_projects() -> tuple[str, ...]:
    return tuple(sorted(_PROJECT_DIRECT_RENDERERS))



def direct_c_renderers_for_project(project: str, repo_root: str | Path = ".") -> dict[str, object]:
    try:
        factory = _PROJECT_DIRECT_RENDERERS[project]
    except KeyError as exc:
        raise ValueError(
            f"unsupported project '{project}'; expected one of: {', '.join(supported_projects())}"
        ) from exc
    return factory(repo_root)
