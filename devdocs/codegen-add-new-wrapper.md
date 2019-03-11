# How to add new language wrapper to the code generation.

[TOC]

## Make POC

1. Write `hello world` example and add it to the CMake build system if needed.
2. Write a simple test for `hello world`  add it to the CMake build system.
3. Select a small library like `Ratchet` or `PHE`.
4. Create a handwritten wrapper for selected library.
5. Add a test for each wrapped method.



## Entities to be generated

Entities are sorted by generation simplicity.

- Enumeration
- Class (without any inherited interfaces)
  - Constant
  - Method
- Interface
- Class (with at least one implemented interface)



## Generation entrypoint

1. Create file `<lang>.gsl` with methods:
    - <lang>_resolve (project, wrapper, projects_api)
    - <lang>_create_project_module (project, destination, wrapper)
    - <lang>_create_c_context_module (source, destination, wrapper, meta)
    - <lang>_create_interface_module (source, destination, wrapper, meta)
    - <lang>_create_implementation_module (source, destination, wrapper, meta)
    - <lang>_finalize_implementation_helper_modules (destination, wrapper, meta) [optional]
    - <lang>_create_class_module (source, destination, wrapper, meta)
    - <lang>_create_enum_module (source, destination, wrapper, meta)
    - <lang>_module_resolve(source, wrapper)
2. Create file `<lang>_codegen.gsl` with methods:
    - <lang>_generate_project(source, wrapper)
    - <lang>_generate_sources(source, wrapper)
3. Add `gsl from "<lang>.gsl"` to this file.
4. Add `gsl from "<lang>_codegen.gsl"` to `<lang>.gsl` file.
5. Create file `models/wrapper/wrapper_<lang>.xml`
6. Add entity `<wrapper lang="<lang>"/>` to main project.
7. For each project that should be wrapped update property `wrappers` by adding `<lang>`, for instance `<project wrappers="swift, php"/>`.


## Enum `error` wrap strategy

Enum `error` is a special enumeration that contains library error codes.

It should be transformed into a language-specific error.




## Class wrap strategy

1. Define `proxy context` - it is pointer to the target C class (context).
2. Add `constructor` that create `proxy context`.
3. Add `destructor` that delete `proxy context`.
4. Possible hide utility methods, that returns minimum capacity of the output buffer.



## Map arguments

- Map primitive types as: integer, size, byte, etc.
- Map interface.
- Map implementation.
- Map special class "data".
- Map special class "buffer".
- Map errors.



## Method signature wrap strategy

1. Map input arguments.
2. Map output arguments (result).
3. If output arguments more than one, they CAN BE returned as `tuple` or as an object of `result class`.



## Method body implementation strategy

1. Map argument with type `data ` to `C` type `vsc_data_t`.
2. Map argument `buffer`to the `C` type `vsc_buffer_t`.
3. Map primitive types.
4. Call the wrapped method.
5. Handle returned error code.
6. If success wrap returned result as `tuple` or as an object of `result class`.
