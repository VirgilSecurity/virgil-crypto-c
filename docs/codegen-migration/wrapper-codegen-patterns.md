# Wrapper Codegen Patterns & Lessons Learned

Patterns discovered during the GSL-to-Python codegen migration for all 6
wrapper languages. These apply to any future wrapper backend or IR changes.

## IR-to-Wrapper Type Mapping

### Primitive types

| IR `type_name` | IR `type_size` | Go | Swift | Java | Python (ctypes) | JS/WASM |
|---|---|---|---|---|---|---|
| `size` | - | `uint` | `Int` | `int` | `c_size_t` | `number` |
| `boolean` | - | `bool` | `Bool` | `boolean` | `c_bool` | `boolean` |
| `integer` | `1` | `int8` | `Int8` | `byte` | `c_int8` | `number` |
| `integer` | `2` | `int16` | `Int16` | `short` | `c_int16` | `number` |
| `integer` | `4` (default) | `int32` | `Int32` | `int` | `c_int32` | `number` |
| `integer` | `8` | `int64` | `Int64` | `long` | `c_int64` | `number` |
| `unsigned` | `1` | `uint8` | `UInt8` | `int` | `c_uint8` | `number` |
| `unsigned` | `2` | `uint16` | `UInt16` | `int` | `c_uint16` | `number` |
| `unsigned` | `4` (default) | `uint32` | `UInt32` | `int` | `c_uint32` | `number` |
| `unsigned` | `8` | `uint64` | `UInt64` | `long` | `c_uint64` | `number` |
| `byte` (array) | - | `[]byte` | `UnsafeMutablePointer<UInt8>` | `byte[]` | `POINTER(c_byte)` | `Uint8Array` |
| `byte` (reference) | - | `unsafe.Pointer` | `UnsafeMutablePointer<UInt8>` | `byte[]` | `POINTER(c_byte)` | `number` |
| `string` | - | `string` | `String` | `String` | `c_char_p` | `string` |

**Key lesson:** Always use sized integer types (`Int32`, `UInt32`), not
platform-dependent `Int`/`UInt`, for interop with C. Swift's `Int` is 64-bit
on modern platforms but C enums/returns may be 32-bit.

### Class/Interface references

| IR field | Meaning | Go | Swift | Java | Python |
|---|---|---|---|---|---|
| `class_name="data"` | Input byte data | `[]byte` | `Data` | `byte[]` | `bytes`/`bytearray` |
| `class_name="buffer"` (arg) | Output buffer | `[]byte` (return) | `Data` (return) | `byte[]` (return) | `Buffer` |
| `class_name="buffer"` (return) | Buffer result | `[]byte` | `Data` | `byte[]` | `bytearray` |
| `class_name="error"` | Error struct | hidden (error return) | hidden (throws) | hidden (exception) | hidden (status) |
| `class_name="self"` | Self-referential | concrete type | concrete type | concrete type | concrete type |
| `interface_name` | Protocol/interface | interface type | protocol type | interface type | abstract class |
| `class_name` (other) | Concrete class | `*ClassName` | `ClassName` | `ClassName` | `ClassName` |

### Special IR patterns

**`class_name="self"`**: Self-referential linked list nodes (e.g.,
`key_recipient_info_list.next` returns `self`). Resolve to the enclosing
entity's concrete type name. Do NOT use Swift's `Self` type (that's for
protocols only, not classes).

**`access="disown"`**: Ownership transfer — the C function takes a `**ptr`
(pointer-to-pointer). In Swift, do `shallow_copy` + pass `&copy`. In Go,
the cgo cast handles this. In Python, pass the ctx directly (ctypes
handles pointer boxing).

**`access="retain"`**: The C function retains a reference. In Swift/Go,
pass `.c_ctx`/`.Ctx()` directly — the C side does its own shallow copy.

**External library types** (`library="mbedtls"` etc.): Skip these in
wrapper generation — they're internal C types not exposed to wrapper APIs.

## Status/Error Handling

Three error patterns in the IR:

1. **Status return**: `method.returns` has `enum_name="status"`. The method
   returns a status code that the wrapper checks and throws/raises.
   - Swift: `try {Project}Error.handleStatus(fromC: proxyResult)`
   - Go: `{Project}ErrorHandleStatus(proxyResult)`
   - Python: `VscfStatus.handle_status(status)`
   - Java: `FoundationJNI.INSTANCE.xxx(...)` (JNI C code checks internally)

2. **Error struct**: `class_name="error"` argument. Allocate a C error
   struct, pass its pointer, then check `error.status` after the call.
   - Swift: `var error: {prefix}_error_t = {prefix}_error_t(); {prefix}_error_reset(&error); ... try handleStatus(fromC: error.status)`
   - Go: `var error C.{prefix}_error_t; C.{prefix}_error_reset(&error); ... HandleStatus(error.status)`
   - Python: `error = {prefix}_error_t(); ... VscfStatus.handle_status(error.status)`

3. **Interface return + error**: Methods returning `interface_name` always
   have an implicit error path (NULL return = failure). The wrapper must
   check for NULL before dispatching through the impl-tag system.

## Buffer Management

### Buffer output arguments (`class_name="buffer"`, `access="writeonly"`)

These are promoted from arguments to return values in the wrapper API.

**Capacity** comes from `arg.length_attrs`:
- `{"constant": "digest len"}` → `self.DIGEST_LEN` (or `self.digestLen` in Swift)
- `{"constant": "X", "class": "phe common"}` → `PheCommon.X` (cross-class)
- `{"method": "encrypt len", "proxy_0_argument": "data", "proxy_0_to": "data_len", "proxy_0_cast": "data_length"}` → `self.encryptLen(dataLen: len(data))`
- `{"argument": "data_len"}` → pass through the argument value

**Key lesson (proxy arguments):** When `length_attrs` has `proxy_{N}_to`,
use the `_to` value as the keyword argument name in the length method call,
NOT the `_argument` value. The `_argument` is the source data, `_to` is the
target parameter name on the length method.

### Buffer lifecycle per language

| Step | Swift | Go | Python |
|---|---|---|---|
| Allocate | `var buf = Data(count: cap)` | `buf, err := newBuffer(cap)` | `buf = Buffer(cap)` |
| Create C buf | `let cBuf = vsc_buffer_new()` | `buf.ctx` (embedded) | `buf.c_buffer` |
| Use | `vsc_buffer_use(cBuf, ptr, cap)` | via `newBuffer` | via `Buffer.__init__` |
| Call | pass `cBuf` to C | pass `buf.ctx` | pass `buf.c_buffer` |
| Extract | `buf.count = vsc_buffer_len(cBuf)` | `buf.getData()` | `buf.get_bytes()` |
| Cleanup | `defer { vsc_buffer_delete(cBuf) }` | `defer buf.delete()` | GC / `__del__` |

## Multi-Buffer Returns (Result Structs)

When a method has 2+ buffer outputs, a result struct is needed:

- **Naming**: `{EntityPascal}{MethodPascal}Result`
  - Protocol methods: use the interface name (e.g., `AuthEncryptAuthEncryptResult`)
  - Class methods: use the class name (e.g., `BrainkeyClientBlindResult`)
  - **Implementations inherit from interfaces**: use the INTERFACE name for
    the result struct, not the implementation name

- **Generated in**: the protocol/class file, after the main type declaration

## Impl-Tag Dispatch

The `impl/tag` enum maps integer tags to concrete implementation classes.
Used for polymorphic return values (C returns `vscf_impl_t*`, wrapper
dispatches to concrete class via tag).

**Key lesson:** The C enum starts with `{prefix}_impl_tag_BEGIN = 0`,
then real tags from 1. The IR omits the `BEGIN` sentinel, so wrapper
dispatch tables must start numbering at 1, not 0.

## Constant Expression Resolution

IR constant values may contain:
- Plain integers: `"32"`, `"0x01"`
- Arithmetic: `"1024 * 1024 - 64"` → evaluate to `1048512`
- GSL references: `".(c_class_xxx_constant_yyy) + 1"` → look up constant
  `yyy` on entity `xxx`, substitute, then evaluate
- C booleans: `"true"`/`"false"` → Python needs `"True"`/`"False"`

Use `resolve_constant_value()` from `project_ir.py` for all constant
emissions across all backends.

## Swift-Specific Patterns

### @objc Limitations
- Enums CANNOT have `@objc` methods (use `internal` for `handleStatus`)
- Methods that `throw` cannot return non-bridgeable types
  (`Int`, `Int32`, `Bool`, `UInt32`, etc.) with `@objc` — omit `@objc`
- Protocols can have `@objc` on all members

### Nested Closures
When a method has data inputs AND buffer outputs, nested
`withUnsafeBytes`/`withUnsafeMutableBytes` closures are generated. Each
intermediate closure that has a multi-statement body (e.g., `vsc_buffer_use`
before the inner call) needs an explicit `return` before the inner closure.

### Cross-Project Imports
Projects that reference types from other projects (e.g., Ratchet using
Foundation's `PrivateKey`) need `import VirgilCryptoFoundation` in their
Swift files. Detect via `arg.project` on method arguments/returns.

### Framework Header Packaging
Interface and implementation public headers must be in the
`MACOSX_PACKAGE_LOCATION` set for xcframework packaging. The CMake backend
must add them to `public_headers` alongside module/class headers.

Infrastructure files (`{prefix}_api.h`, `{prefix}_impl_private.h`) are
unconditional when the project has interfaces.
