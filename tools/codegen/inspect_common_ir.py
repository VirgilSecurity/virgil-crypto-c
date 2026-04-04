#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.codegen.common_ir import project_common_to_ir
from tools.codegen.common_source import load_project_source, project_common_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--module")
    parser.add_argument("--class-name")
    args = parser.parse_args()

    ir = project_common_to_ir(load_project_source(project_common_path(args.repo_root)))
    if args.module:
        obj = next((m for m in ir.modules if m.name == args.module), None)
        if obj is None:
            raise SystemExit(f"module not found: {args.module}")
        print(json.dumps(obj.__dict__, indent=2, default=lambda o: o.__dict__))
        return 0
    if args.class_name:
        obj = next((c for c in ir.classes if c.name == args.class_name), None)
        if obj is None:
            raise SystemExit(f"class not found: {args.class_name}")
        print(json.dumps(obj.__dict__, indent=2, default=lambda o: o.__dict__))
        return 0

    summary = {
        "project": ir.name,
        "prefix": ir.prefix,
        "include_namespace": ir.include_namespace,
        "modules": [m.name for m in ir.modules],
        "dependency_modules": [m.name for m in ir.dependency_modules],
        "classes": [c.name for c in ir.classes],
        "enums": [e.name for e in ir.enums],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
