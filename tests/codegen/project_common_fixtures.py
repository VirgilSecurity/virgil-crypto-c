from __future__ import annotations

PROJECT_COMMON_EXPECTATIONS = {
    "project": {
        "name": "common",
        "namespace": "virgil crypto common",
        "framework": "VSCCommon",
        "prefix": "vsc",
        "path": "../library/common/",
        "work_path": "generated/common/",
        "wrappers": "python",
        "version": {"major": "0", "minor": "17", "patch": "3"},
        "features": [
            {"name": "multi threading", "default": "on"},
        ],
    },
    "module_names": ["assert", "library", "memory", "atomic"],
    "class_names": ["data", "buffer"],
    "enum_names": [],
    "module_facts": {
        "assert": {
            "requires": ["library"],
            "callbacks": ["handler"],
            "methods": ["change handler", "abort", "trigger", "path basename"],
        },
        "library": {
            "requires": ["platform"],
            "macros": ["major", "minor", "patch", "make", "version", "nodiscard", "noreturn", "ceil", "unused"],
        },
        "atomic": {
            "requires": ["library"],
            "methods": ["compare exchange weak"],
            "code_snippets": ["_InterlockedCompareExchange", "Atomic operations are not suppored"],
        },
    },
    "class_facts": {
        "data": {
            "properties": ["bytes", "len"],
            "constructors": ["data", "from str", "empty"],
            "methods": ["is valid", "is zero", "is empty", "equal", "len", "bytes", "secure equal", "slice beg", "slice end"],
        },
        "buffer": {
            "properties": ["bytes_dealloc", "bytes", "capacity", "len", "is secure", "is owner", "is reverse"],
            "constructors": ["with capacity", "with data"],
            "methods": ["is empty", "is reverse", "equal", "secure equal", "alloc", "release", "use", "take", "make secure", "switch reverse mode"],
        },
    },
}
