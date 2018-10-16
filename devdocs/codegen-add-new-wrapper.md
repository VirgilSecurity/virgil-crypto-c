# How to add wrapper of new language to the code generation.

[TOC]

## Write file `<lang>_module.xnf`

This file should provide model specification of the wrapped language constructions, for instance:

- `<lang>_class` - contains information required to generate class;
- `<lang>_method` - contains information required to generate method;
- `<lang>_variable` - contains information required to generate variable.

## Map Interface

1. Define how interface represented in the target language.
2. Define what information is necessary to generate interface.

## Methods wrap strategy

1. Map input arguments.
2. Call wrapped method.
3. Handle error.
4. Map output arguments (result).

## Map arguments

- Map primitive types as: integer, size, byte, etc.
- Map interface.
- Map implementation.
- Map special class "data".
- Map special class "buffer".
- Map errors.