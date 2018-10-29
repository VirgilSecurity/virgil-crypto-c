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

## Enum `error` wrap strategy

Enum `error` is a special enumeration that contains library error codes.

1. Declare method or global function that can transform error code to the 


## Class wrap strategy

1. Define `proxy context` - it is pointer to the target C class (context).
2. Add `constructor` that create `proxy context`.
3. Add `destructor`that delete `proxy context`.
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
3. If output orgumenrs more than one, thay CAN BE retunred as `tuple` or as object of `result class`. 

## Method body implementation strategy

1. Map argument with type `data ` to `C` type `vsc_data_t`.
2. Map argument `buffer`to the `C` type `vsc_buffer_t`.
3. Map primitive types.
4. Call wrapped method.
5. handle returned error code.
6. If success wrap returned result as `tuple` or as object of `result class`. 
