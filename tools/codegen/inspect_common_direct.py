#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.codegen.common_direct_c import build_direct_data_c_module


def elem_to_dict(elem: ET.Element):
    return {
        'tag': elem.tag,
        'attrs': dict(elem.attrib),
        'text': (elem.text or '').strip(),
        'children': [elem_to_dict(c) for c in list(elem)],
    }


if __name__ == '__main__':
    root = build_direct_data_c_module('.')
    print(json.dumps(elem_to_dict(root), indent=2))
