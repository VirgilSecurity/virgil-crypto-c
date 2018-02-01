Base model for C language code generation.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <c_gmodule name output_source_file header_file source_file output_header_file once_guard
         [class] [scope]>
       <c_alias name type/>
       <c_enum [visibility] [scope] [name]>
          <c_enum_value [name] [value]/>
       </c_enum>
       <c_struct [name]>
          <c_struct_property name [formatted]>
             <c_type base [is_callback] [kind] [array] [is_const_type] [is_const_pointer] [is_const_array]
                  [is_const_reference]/>
             <c_return>
                <c_type .../>
             </c_return>
             <c_argument name [formatted]>
                <c_type .../>
             </c_argument>
          </c_struct_property>
       </c_struct>
       <c_object type name [scope] [visibility]>
          <c_object_value value [formatted]>
             <c_type .../>
             <c_modifier [value]/>
          </c_object_value>
          <c_modifier .../>
       </c_object>
       <c_method name [scope] [visibility]>
          <c_modifier .../>
          <c_return .../>
          <c_argument .../>
          <c_precondition [position]/>
       </c_method>
       <c_macros [scope] [is_method]>
          <c_implementation/>
       </c_macros>
    </c_gmodule>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'c_gmodule' item
--------------------

Base model for C language code generation.

    <c_gmodule
        name = "..."
        output_source_file = "..."
        header_file = "..."
        source_file = "..."
        output_header_file = "..."
        once_guard = "..."
      [ class = "..." ]
      [ scope = "public | private"  ("public") ]
        >
        <c_alias>
        <c_enum>
        <c_struct>
        <c_object>
        <c_method>
        <c_macros>
    </c_gmodule>

The c_gmodule item can have these attributes:

name:
    Short module name. The name attribute is required.

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

header_file:
    Name of the generated header file without path. The header_file attribute
    is required.                                                             

source_file:
    Name of the generated source file without path. The source_file attribute
    is required.                                                             

output_header_file:
    Path to the header file that will be generated. The output_header_file
    attribute is required.                                                

output_source_file:
    Path to the source file that will be generated. The output_source_file
    attribute is required.                                                

once_guard:
    String that is used as C header guard. The once_guard attribute is
    required.                                                         

scope:
    Defines whether this module be accessible for the library clients. The 
    scope attribute is optional. Its default value is "public". It can take
    one of the following values:                                           

Value: Meaning:
public: Module is visible for outside world. Header is copied to the public section.
private: Module is visible only within library. Header is copied to the private section.


The 'c_alias' item
------------------

Define synonym for the given type.

    <c_alias
        name = "..."
        type = "..."
        />

The c_alias item can have these attributes:

name:
    Alias name. The name attribute is required.

type:
    Alias type. The type attribute is required.


The 'c_enum' item
-----------------

Defines enumeration type.

    <c_enum
      [ visibility = "public | private"  ("public") ]
      [ scope = "public | private | opqaue | external"  ("public") ]
      [ name = "..." ]
        >
        <c_enum_value>, 1 or more
    </c_enum>

The c_enum item can have these attributes:

visibility:
    Defines symbol visibility. The visibility attribute is optional. Its
    default value is "public". It can take one of the following values: 

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines module visibility. The scope attribute is optional. Its default
    value is "public". It can take one of the following values:            

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.
opqaue: Component declaration is visible for outside world. Component definition is hidden in a correspond source file.
external: Component declaration is visible for outside world. Component definition is located somewhere.

name:
    Enumeration name. Can be ommited if it is used to define named constants.
    The name attribute is optional.                                          


The 'c_enum_value' item
-----------------------

Define enumeration value.

    <c_enum_value
      [ name = "..." ]
      [ value = "..." ]
        />

The c_enum_value item can have these attributes:

name:
    Value name. The name attribute is optional.

value:
    Integral enumeration value. The value attribute is optional.


The 'c_struct' item
-------------------

Define structure type.

    <c_struct
      [ name = "..." ]
        >
        <c_struct_property>, 1 or more
    </c_struct>

The c_struct item has this single attribute:

name:
    Structure name. The name attribute is optional.


The 'c_struct_property' item
----------------------------

Define property of the structure type.

    <c_struct_property
        name = "..."
      [ formatted = "..." ]
        >
        <c_type>, optional
        <c_return>, optional
        <c_argument>
    </c_struct_property>

The c_struct_property item can have these attributes:

name:
    Property name. The name attribute is required.

formatted:
    Formatted name and type. The formatted attribute is optional.


The 'c_type' item
-----------------

Defines a type of outer component.

    <c_type
        base = "..."
      [ is_callback = "0 | 1"  ("0") ]
      [ kind = "value | pointer | reference"  ("value") ]
      [ array = "var | fixed | derived" ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_reference = "..." ]
        />

The c_type item can have these attributes:

base:
    Type without any modifiers. The base attribute is required.

is_callback:
    Mark type as callback. The is_callback attribute is optional. Its default
    value is "0". It can take one of the following values:                   

Value: Meaning:
0: Just a type.
1: Callback type.

kind:
    Defines a kind of the type. The kind attribute is optional. Its default
    value is "value". It can take one of the following values:             

Value: Meaning:
value: Value type, i.e. 'int'
pointer: Pointer type, i.e. 'int *'
reference: Pointer to pointer type, i.e. 'int **'

array:
    The array attribute is optional. It can take one of the following values:

Value: Meaning:
var: Null-terminated array, or array with a given size, i.e. 'int *'.
fixed: Array with a fixed size, i.e. 'int [32]'.
derived: Array with a derived size, i.e. 'int []'.

is_const_type:
    Defines constness of a type. The is_const_type attribute is optional.

is_const_pointer:
    Defines constness of a pointer. The is_const_pointer attribute is
    optional.                                                        

is_const_array:
    Defines constness of an array. The is_const_array attribute is optional.

is_const_reference:
    Defines constness of a reference. The is_const_reference attribute is
    optional.                                                            


The 'c_return' item
-------------------

Defines return type.

    <c_return>
        <c_type>, required
    </c_return>



The 'c_argument' item
---------------------

Defines method or callback argument.

    <c_argument
        name = "..."
      [ formatted = "..." ]
        >
        <c_type>, required
    </c_argument>

The c_argument item can have these attributes:

name:
    Argument name. The name attribute is required.

formatted:
    Formatted argument name and type. The formatted attribute is optional.


The 'c_object' item
-------------------

Define global object.

    <c_object
        type = "..."
        name = "..."
      [ scope = "public | private | opqaue | external"  ("public") ]
      [ visibility = "public | private"  ("public") ]
        >
        <c_object_value>, 1 or more
        <c_modifier>
    </c_object>

The c_object item can have these attributes:

visibility:
    Defines symbol visibility. The visibility attribute is optional. Its
    default value is "public". It can take one of the following values: 

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines module visibility. The scope attribute is optional. Its default
    value is "public". It can take one of the following values:            

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.
opqaue: Component declaration is visible for outside world. Component definition is hidden in a correspond source file.
external: Component declaration is visible for outside world. Component definition is located somewhere.

name:
    Object name. The name attribute is required.

type:
    Object type. The type attribute is required.


The 'c_object_value' item
-------------------------

Defines one of the object values.

    <c_object_value
        value = "..."
      [ formatted = "..." ]
        >
        <c_type>, optional
        <c_modifier>
    </c_object_value>

The c_object_value item can have these attributes:

value:
    Specific value. If 'c_type' is given then value will be casted to it. The
    value attribute is required.                                             

formatted:
    Formatted object name and type. The formatted attribute is optional.


The 'c_modifier' item
---------------------

Defines object and methods modifiers.

    <c_modifier
      [ value = "..." ]
        />

The c_modifier item has this single attribute:

value:
    Modifier itself. The value attribute is optional.


The 'c_method' item
-------------------

Define method signature and implementation (optional).

    <c_method
        name = "..."
      [ scope = "public | private | opqaue | external"  ("public") ]
      [ visibility = "public | private"  ("public") ]
        >
        <c_modifier>
        <c_return>, optional
        <c_argument>
        <c_precondition>
    </c_method>

The c_method item can have these attributes:

visibility:
    Defines symbol visibility. The visibility attribute is optional. Its
    default value is "public". It can take one of the following values: 

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines module visibility. The scope attribute is optional. Its default
    value is "public". It can take one of the following values:            

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.
opqaue: Component declaration is visible for outside world. Component definition is hidden in a correspond source file.
external: Component declaration is visible for outside world. Component definition is located somewhere.

name:
    Method name. The name attribute is required.


The 'c_precondition' item
-------------------------

Defines method precondition. All preconditions are sorted by position
ascending.                                                           

    <c_precondition
      [ position = "..."  ("0") ]
        />

The c_precondition item has this single attribute:

position:
    Number that defines precondition position. The position attribute is
    optional. Its default value is "0".                                 


The 'c_macros' item
-------------------

Define macros, that can represent a constant or a method.

    <c_macros
      [ scope = "public | private | opqaue | external"  ("public") ]
      [ is_method = "0 | 1"  ("0") ]
        >
        <c_implementation>, optional
    </c_macros>

The c_macros item can have these attributes:

scope:
    Defines module visibility. The scope attribute is optional. Its default
    value is "public". It can take one of the following values:            

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.
opqaue: Component declaration is visible for outside world. Component definition is hidden in a correspond source file.
external: Component declaration is visible for outside world. Component definition is located somewhere.

is_method:
    The is_method attribute is optional. Its default value is "0". It can
    take one of the following values:                                    

Value: Meaning:
0: Macros is a constannt.
1: Macros is a method.


The 'c_implementation' item
---------------------------

Defines method or macros implementation.

    <c_implementation>


