from __future__ import annotations

"""Compatibility adapter for the `common` project source-model entrypoints."""

from pathlib import Path

from tools.codegen.project_source import (
    ArgumentSource,
    ClassSource,
    ConstantSource,
    EnumSource,
    MethodSource,
    ModuleSource,
    NamedRef,
    ProjectFeatureSource,
    ProjectSource,
    PropertySource,
    VariableSource,
    load_class_source,
    load_enum_source,
    load_module_source,
    load_named_project_source,
    load_project_source,
    project_model_path,
)


ProjectCommonSource = ProjectSource

__all__ = [
    "ArgumentSource",
    "ClassSource",
    "ConstantSource",
    "EnumSource",
    "MethodSource",
    "ModuleSource",
    "NamedRef",
    "ProjectCommonSource",
    "ProjectFeatureSource",
    "ProjectSource",
    "PropertySource",
    "VariableSource",
    "load_class_source",
    "load_enum_source",
    "load_module_source",
    "load_project_common",
    "load_project_source",
    "project_common_path",
    "project_model_path",
]


def project_common_path(repo_root: str | Path = ".") -> Path:
    return project_model_path("common", repo_root)


def load_project_common(repo_root: str | Path = ".") -> ProjectCommonSource:
    return load_named_project_source("common", repo_root)
