from __future__ import annotations

from pathlib import Path
import unittest

from tools.codegen.common_ir import project_common_to_ir
from tools.codegen.common_source import load_project_common


REPO_ROOT = Path(__file__).resolve().parents[2]


class ProjectCommonIRTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project = load_project_common(REPO_ROOT)
        cls.ir = project_common_to_ir(cls.project)

    def test_project_common_ir_exposes_project_and_output_metadata(self) -> None:
        ir = self.ir

        self.assertEqual("common", ir.name)
        self.assertEqual("virgil crypto common", ir.namespace)
        self.assertEqual("VSCCommon", ir.framework)
        self.assertEqual("vsc", ir.prefix)
        self.assertEqual(str(REPO_ROOT / "codegen/models/project_common/project_common.xml"), ir.project_path)
        self.assertEqual(str(REPO_ROOT / "library/common"), ir.source_root)
        self.assertEqual(str(REPO_ROOT / "codegen/generated/common"), ir.work_root)
        self.assertEqual("virgil/crypto/common", ir.include_namespace)
        self.assertEqual("generated/common", ir.generated_namespace)
        self.assertEqual(["multi threading"], [feature.name for feature in ir.features])
        self.assertEqual(["assert", "library", "memory", "atomic"], [ref.name for ref in ir.module_refs])
        self.assertEqual(["data", "buffer"], [ref.name for ref in ir.class_refs])
        self.assertEqual([], [ref.name for ref in ir.enum_refs])
        self.assertEqual([], ir.enums)

    def test_project_common_ir_preserves_resolved_graph_and_dependency_modules(self) -> None:
        ir = self.ir

        self.assertEqual(["assert", "library", "memory", "atomic"], [module.name for module in ir.modules])
        self.assertEqual(["platform"], [module.name for module in ir.dependency_modules])
        self.assertEqual(["assert", "library", "platform", "memory", "atomic"], [module.name for module in ir.resolved_modules])

        atomic = next(module for module in ir.resolved_modules if module.name == "atomic")
        self.assertEqual("shared", atomic.from_area)
        self.assertEqual("private", atomic.attrs["scope"])
        self.assertEqual("private", atomic.output.header_visibility)
        self.assertEqual("../library/common/include/virgil/crypto/common/private/vsc_atomic.h", atomic.output.header_path)
        self.assertEqual("../library/common/src/vsc_atomic.c", atomic.output.source_path)
        self.assertEqual("generated/common/module_atomic.xml", atomic.output.generated_source_path)
        self.assertEqual("generated/common/c_module_vsc_atomic.xml", atomic.output.generated_header_path)

    def test_project_common_ir_lowers_modules_with_typed_refs_and_output_targets(self) -> None:
        assert_module = next(module for module in self.ir.modules if module.name == "assert")

        self.assertEqual(["library"], [ref.name for ref in assert_module.requires])
        self.assertEqual("module", assert_module.output.entity_kind)
        self.assertEqual("vsc_assert", assert_module.output.c_symbol)
        self.assertEqual("vsc_assert.h", assert_module.output.include_file)
        self.assertEqual("vsc_assert.c", assert_module.output.source_file)
        self.assertEqual("vsc_assert_h_included", assert_module.output.once_guard)
        self.assertEqual(["handler"], [callback.name for callback in assert_module.callbacks])
        self.assertIn("change handler", [method.name for method in assert_module.methods])
        self.assertEqual("callback", assert_module.variables[0].type_kind)

    def test_project_common_ir_lowers_classes_with_struct_fields_and_output_targets(self) -> None:
        data_class = next(cls for cls in self.ir.classes if cls.name == "data")
        buffer_class = next(cls for cls in self.ir.classes if cls.name == "buffer")

        self.assertEqual("1", data_class.attrs["is_value_type"])
        self.assertEqual(["bytes", "len"], [field.name for field in data_class.struct_fields])
        self.assertEqual("readonly", data_class.struct_fields[0].access)
        self.assertEqual(["data", "from str", "empty"], [ctor.name for ctor in data_class.constructors])
        self.assertEqual("class", data_class.output.entity_kind)
        self.assertEqual("vsc_data", data_class.output.c_symbol)
        self.assertEqual("../library/common/include/virgil/crypto/common/vsc_data.h", data_class.output.header_path)
        self.assertEqual("generated/common/class_data.xml", data_class.output.generated_source_path)

        self.assertEqual(["bytes_dealloc", "bytes", "capacity", "len", "is secure", "is owner", "is reverse"], [field.name for field in buffer_class.struct_fields])
        self.assertEqual("callback", buffer_class.struct_fields[0].type_kind)
        self.assertTrue(buffer_class.struct_fields[1].is_reference)
        self.assertEqual("vsc_buffer", buffer_class.output.c_symbol)


if __name__ == "__main__":
    unittest.main()
