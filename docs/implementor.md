Defines different implementations that is based on the same underlying
library.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <implementor name [is_default]>
       <implementation name>
          <c_include file/>
          <interface name>
             <context name c_type/>
             <constant name value/>
          </interface>
       </implementation>
    </implementor>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'implementor' item
----------------------

Defines different implementations that is based on the same underlying
library

    <implementor
        name = "..."
      [ is_default = "0 | 1"  ("0") ]
        >
        <implementation>, 1 or more
    </implementor>

The implementor item can have these attributes:

name:
    Implementor name - underlying library name that is used for
    implementations. The name attribute is required.

is_default:
    Defines whether implementor is default in the library. The is_default
    attribute is optional. Its default value is "0". It can take one of the
    following values:

Value: Meaning:
0: Implementor is not default, so it's name will be prefixed to types and functions.
1: Implementor is not default, so it's name will will be prefixed as usual.


The 'implementation' item
-------------------------

Defines set of the implemented interfaces in a one module.

    <implementation
        name = "..."
        >
        <c_include>
        <interface>, 1 or more
    </implementation>

The implementation item has this single attribute:

name:
    Implementation name. The name attribute is required.


The 'c_include' item
--------------------

Defines C header file that is used for implementation.

    <c_include
        file = "..."
        />

The c_include item has this single attribute:

file:
    File name to be included. The file attribute is required.


The 'interface' item
--------------------

Provide information about implemented interface.

    <interface
        name = "..."
        >
        <context>
        <constant>
    </interface>

The interface item has this single attribute:

name:
    Name of the implemented interface. The name attribute is required.


The 'context' item
------------------

Defines specific underlying implementation context.

    <context
        name = "..."
        c_type = "..."
        />

The context item can have these attributes:

name:
    Name of the context. The name attribute is required.

c_type:
    C type of the underlying context. The c_type attribute is required.


The 'constant' item
-------------------

Defines specific value for interface constant.

    <constant
        name = "..."
        value = "..."
        />

The constant item can have these attributes:

name:
    Name of the interface constant. The name attribute is required.

value:
    Value of the interface constant. Note, value must be integral. The value
    attribute is required.

