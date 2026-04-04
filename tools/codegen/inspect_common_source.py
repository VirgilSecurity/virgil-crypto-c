#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.codegen.common_source import load_project_source, project_common_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--module")
    parser.add_argument("--class-name")
    args = parser.parse_args()

    project = load_project_source(project_common_path(args.repo_root))
    if args.module:
        obj = next((m for m in project.modules if m.name == args.module), None)
        if obj is None:
            raise SystemExit(f"module not found: {args.module}")
        print(json.dumps(obj.__dict__, indent=2, default=lambda o: o.__dict__))
        return 0
    if args.class_name:
        obj = next((c for c in project.classes if c.name == args.class_name), None)
        if obj is None:
            raise SystemExit(f"class not found: {args.class_name}")
        print(json.dumps(obj.__dict__, indent=2, default=lambda o: o.__dict__))
        return 0

    summary = {
        "project": project.name,
        "modules": [m.name for m in project.modules],
        "classes": [c.name for c in project.classes],
        "counts": {
            "modules": len(project.modules),
            "classes": len(project.classes),
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
