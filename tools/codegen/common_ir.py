from __future__ import annotations

from tools.codegen.project_ir import (
    IRArgument,
    IRClass,
    IRCommented,
    IRConstant,
    IREntityRef,
    IREnum,
    IRFeature,
    IRMethod,
    IRModule,
    IROutputTarget,
    IRProject,
    IRProject as IRProjectCommon,
    IRStructField,
    IRVariable,
    build_output_target,
    class_to_ir,
    enum_to_ir,
    generated_namespace,
    module_to_ir,
    output_once_guard,
    project_include_namespace,
    project_to_ir,
)
from tools.codegen.project_source import ProjectSource


IRCArgument = IRArgument
IRCMethod = IRMethod
IRCVariable = IRVariable
IRCConstant = IRConstant
IRCModule = IRModule
IRCStructField = IRStructField


def project_common_to_ir(project: ProjectSource) -> IRProjectCommon:
    return project_to_ir(project)
