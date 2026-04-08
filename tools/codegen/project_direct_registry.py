from __future__ import annotations

"""Shared registry for project-specific direct C renderer adapters."""

from collections.abc import Callable
from pathlib import Path

from tools.codegen.project_c_backend import direct_xml_name, render_enum_c_module
from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source


DirectRendererFactory = Callable[[str | Path], dict[str, object]]



def _common_renderers(repo_root: str | Path = ".") -> dict[str, object]:
    from tools.codegen.common_direct_c import direct_c_renderers

    return direct_c_renderers(repo_root)



def _noop_renderers(repo_root: str | Path = ".") -> dict[str, object]:
    del repo_root
    return {}


_PROJECT_DIRECT_RENDERERS: dict[str, DirectRendererFactory] = {
    "common": _common_renderers,
    "foundation": _noop_renderers,
}



def supported_projects() -> tuple[str, ...]:
    return tuple(sorted(_PROJECT_DIRECT_RENDERERS))



def _shared_enum_renderers(project: str, repo_root: str | Path = ".") -> dict[str, object]:
    project_ir = project_to_ir(load_named_project_source(project, repo_root))
    return {
        direct_xml_name(enum.output): (
            lambda _repo_root, project_ir=project_ir, enum=enum: render_enum_c_module(project_ir, enum)
        )
        for enum in project_ir.enums
    }



def direct_c_renderers_for_project(project: str, repo_root: str | Path = ".") -> dict[str, object]:
    try:
        factory = _PROJECT_DIRECT_RENDERERS[project]
    except KeyError as exc:
        raise ValueError(
            f"unsupported project '{project}'; expected one of: {', '.join(supported_projects())}"
        ) from exc
    return {
        **factory(repo_root),
        **_shared_enum_renderers(project, repo_root),
    }
