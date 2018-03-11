Base model for C language code generation.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <c_module output_source_file once_guard name header_file source_file output_header_file
         [class] [scope]>
       <c_include file [scope] [is_system]/>
       <c_alias name type/>
       <c_enum [uid] [definition] [visibility] [scope] [name]>
          <c_constant name [scope] [uid] [value]/>
       </c_enum>
       <c_struct name [uid]>
          <c_property type name [is_callback] [kind] [array] [length] [is_const_type] [is_const_pointer]
               [is_const_array] [is_const_reference] [uid] [is_string]/>
       </c_struct>
       <c_variable type name [is_callback] [kind] [array] [length] [is_const_type] [is_const_pointer]
            [is_const_array] [is_const_reference] [uid] [visibility] [scope]
            [is_string]>
          <c_value value [cast]/>
          <c_modifier [value]/>
       </c_variable>
       <c_method name [definition] [visibility] [scope] [uid]>
          <c_modifier .../>
          <c_return type [is_callback] [is_string] [kind] [array] [length] [is_const_type] [is_const_pointer]
               [is_const_array] [is_const_reference]/>
          <c_argument type name [is_callback] [kind] [array] [length] [is_const_type] [is_const_pointer]
               [is_const_array] [is_const_reference] [uid] [is_string]/>
          <c_precondition [position]/>
       </c_method>
       <c_callback name [visibility] [scope] [uid]>
          <c_return .../>
          <c_argument .../>
       </c_callback>
       <c_macros [uid] [scope] [is_method]>
          <c_implementation/>
       </c_macros>
    </c_module>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'c_module' item
-------------------

Base model for C language code generation.

    <c_module
        output_source_file = "..."
        once_guard = "..."
        name = "..."
        header_file = "..."
        source_file = "..."
        output_header_file = "..."
      [ class = "..." ]
      [ scope = "public | private"  ("public") ]
        >
        <c_include>
        <c_alias>
        <c_enum>
        <c_struct>
        <c_variable>
        <c_method>
        <c_callback>
        <c_macros>
    </c_module>

The c_module item can have these attributes:

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Short module name. The name attribute is required.

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


The 'c_include' item
--------------------



    <c_include
        file = "..."
      [ scope = "public | private"  ("public") ]
      [ is_system = "0 | 1"  ("0") ]
        />

The c_include item can have these attributes:

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

file:
    File name to be included. The file attribute is required.

is_system:
    The is_system attribute is optional. Its default value is "0". It can
    take one of the following values:                                    

Value: Meaning:
0: Included file is enclosed in: "file"
1: Included file is enclosed in: &lt;file&gt;


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
      [ uid = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ visibility = "public | private"  ("public") ]
      [ scope = "public | private"  ("public") ]
      [ name = "..." ]
        >
        <c_constant>, 1 or more
    </c_enum>

The c_enum item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

definition:
    Defines where component will be defined. This attribute must not be  
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:                  

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:                                  

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Enumeration name. Can be omitted if it is used to define named constants.
    The name attribute is optional.                                          


The 'c_constant' item
---------------------

Defines integral constant.

    <c_constant
        name = "..."
      [ scope = "public | private"  ("public") ]
      [ uid = "..." ]
      [ value = "..." ]
        />

The c_constant item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Constant name. The name attribute is required.

value:
    Constant value. The value attribute is optional.


The 'c_struct' item
-------------------

Define structure type.

    <c_struct
        name = "..."
      [ uid = "..." ]
        >
        <c_property>, 1 or more
    </c_struct>

The c_struct item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

name:
    Structure name. The name attribute is required.


The 'c_property' item
---------------------

Defines a type of outer component. Define property of the structure type.

    <c_property
        type = "..."
        name = "..."
      [ is_callback = "0 | 1"  ("0") ]
      [ kind = "value | pointer | reference"  ("value") ]
      [ array = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_reference = "..." ]
      [ uid = "..." ]
      [ is_string = "0 | 1" ]
        />

The c_property item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

is_callback:
    Mark type as callback. The is_callback attribute is optional. Its default
    value is "0". It can take one of the following values:                   

Value: Meaning:
0: Just a type.
1: Callback type.

is_string:
    Mark type as a string - specal class. The is_string attribute is
    optional. It can take one of the following values:              

Value: Meaning:
0: User defined type.
1: String.

kind:
    Defines instance kind of the type. The kind attribute is optional. Its
    default value is "value". It can take one of the following values:    

Value: Meaning:
value: Value type, i.e. 'int'
pointer: Pointer type, i.e. 'int *'
reference: Pointer to pointer type, i.e. 'int **'

array:
    Defines array length type. If given, parent instance becomes an array.   
    The array attribute is optional. It can take one of the following values:

Value: Meaning:
null_terminated: Null-terminated array.
given: Array with a given length, i.e. 'int *'.
fixed: Array with a fixed length, i.e. 'int [32]'.
derived: Array with a derived length, i.e. 'int []'.

length:
    Defines length constant for the fixed array. Note, this attribute is
    ignored for other arrays. The length attribute is optional.         

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.                                  

is_const_array:
    Defines array constness . The is_const_array attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.                          

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

name:
    Property name. The name attribute is required.


The 'c_variable' item
---------------------

Defines a type of outer component. Define global variable.

    <c_variable
        type = "..."
        name = "..."
      [ is_callback = "0 | 1"  ("0") ]
      [ kind = "value | pointer | reference"  ("value") ]
      [ array = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_reference = "..." ]
      [ uid = "..." ]
      [ visibility = "public | private"  ("public") ]
      [ scope = "public | private"  ("public") ]
      [ is_string = "0 | 1" ]
        >
        <c_value>, 1 or more
        <c_modifier>
    </c_variable>

The c_variable item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

is_callback:
    Mark type as callback. The is_callback attribute is optional. Its default
    value is "0". It can take one of the following values:                   

Value: Meaning:
0: Just a type.
1: Callback type.

is_string:
    Mark type as a string - specal class. The is_string attribute is
    optional. It can take one of the following values:              

Value: Meaning:
0: User defined type.
1: String.

kind:
    Defines instance kind of the type. The kind attribute is optional. Its
    default value is "value". It can take one of the following values:    

Value: Meaning:
value: Value type, i.e. 'int'
pointer: Pointer type, i.e. 'int *'
reference: Pointer to pointer type, i.e. 'int **'

array:
    Defines array length type. If given, parent instance becomes an array.   
    The array attribute is optional. It can take one of the following values:

Value: Meaning:
null_terminated: Null-terminated array.
given: Array with a given length, i.e. 'int *'.
fixed: Array with a fixed length, i.e. 'int [32]'.
derived: Array with a derived length, i.e. 'int []'.

length:
    Defines length constant for the fixed array. Note, this attribute is
    ignored for other arrays. The length attribute is optional.         

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.                                  

is_const_array:
    Defines array constness . The is_const_array attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.                          

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:                                  

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Object name. The name attribute is required.


The 'c_value' item
------------------

Defines specific variable value.

    <c_value
        value = "..."
      [ cast = "..." ]
        />

The c_value item can have these attributes:

value:
    Specific value. The value attribute is required.

cast:
    Cast a value to the given type. The cast attribute is optional.


The 'c_modifier' item
---------------------

Defines variable or methods modifiers, i.e. visibility, static, etc.

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
      [ definition = "public | private | external"  ("private") ]
      [ visibility = "public | private"  ("public") ]
      [ scope = "public | private"  ("public") ]
      [ uid = "..." ]
        >
        <c_modifier>
        <c_return>, optional
        <c_argument>
        <c_precondition>
    </c_method>

The c_method item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

definition:
    Defines where component will be defined. This attribute must not be  
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:                  

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:                                  

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Method name. The name attribute is required.


The 'c_return' item
-------------------

Defines a type of outer component. Defines return type.

    <c_return
        type = "..."
      [ is_callback = "0 | 1"  ("0") ]
      [ is_string = "0 | 1" ]
      [ kind = "value | pointer | reference"  ("value") ]
      [ array = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_reference = "..." ]
        />

The c_return item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

is_callback:
    Mark type as callback. The is_callback attribute is optional. Its default
    value is "0". It can take one of the following values:                   

Value: Meaning:
0: Just a type.
1: Callback type.

is_string:
    Mark type as a string - specal class. The is_string attribute is
    optional. It can take one of the following values:              

Value: Meaning:
0: User defined type.
1: String.

kind:
    Defines instance kind of the type. The kind attribute is optional. Its
    default value is "value". It can take one of the following values:    

Value: Meaning:
value: Value type, i.e. 'int'
pointer: Pointer type, i.e. 'int *'
reference: Pointer to pointer type, i.e. 'int **'

array:
    Defines array length type. If given, parent instance becomes an array.   
    The array attribute is optional. It can take one of the following values:

Value: Meaning:
null_terminated: Null-terminated array.
given: Array with a given length, i.e. 'int *'.
fixed: Array with a fixed length, i.e. 'int [32]'.
derived: Array with a derived length, i.e. 'int []'.

length:
    Defines length constant for the fixed array. Note, this attribute is
    ignored for other arrays. The length attribute is optional.         

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.                                  

is_const_array:
    Defines array constness . The is_const_array attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.                          


The 'c_argument' item
---------------------

Defines a type of outer component. Defines method or callback argument.

    <c_argument
        type = "..."
        name = "..."
      [ is_callback = "0 | 1"  ("0") ]
      [ kind = "value | pointer | reference"  ("value") ]
      [ array = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_reference = "..." ]
      [ uid = "..." ]
      [ is_string = "0 | 1" ]
        />

The c_argument item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

is_callback:
    Mark type as callback. The is_callback attribute is optional. Its default
    value is "0". It can take one of the following values:                   

Value: Meaning:
0: Just a type.
1: Callback type.

is_string:
    Mark type as a string - specal class. The is_string attribute is
    optional. It can take one of the following values:              

Value: Meaning:
0: User defined type.
1: String.

kind:
    Defines instance kind of the type. The kind attribute is optional. Its
    default value is "value". It can take one of the following values:    

Value: Meaning:
value: Value type, i.e. 'int'
pointer: Pointer type, i.e. 'int *'
reference: Pointer to pointer type, i.e. 'int **'

array:
    Defines array length type. If given, parent instance becomes an array.   
    The array attribute is optional. It can take one of the following values:

Value: Meaning:
null_terminated: Null-terminated array.
given: Array with a given length, i.e. 'int *'.
fixed: Array with a fixed length, i.e. 'int [32]'.
derived: Array with a derived length, i.e. 'int []'.

length:
    Defines length constant for the fixed array. Note, this attribute is
    ignored for other arrays. The length attribute is optional.         

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.                                  

is_const_array:
    Defines array constness . The is_const_array attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.                          

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

name:
    Argument name. The name attribute is required.


The 'c_precondition' item
-------------------------

Defines method precondition. All preconditions are sorted by position
ascending.                                                           

    <c_precondition
      [ position = "..."  ("0") ]
        />

The c_precondition item has this single attribute:

position:
    Position's weight of the precondition. The position attribute is
    optional. Its default value is "0".                             


The 'c_callback' item
---------------------

Define callback type.

    <c_callback
        name = "..."
      [ visibility = "public | private"  ("public") ]
      [ scope = "public | private"  ("public") ]
      [ uid = "..." ]
        >
        <c_return>, optional
        <c_argument>
    </c_callback>

The c_callback item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:                                  

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Method name. The name attribute is required.


The 'c_macros' item
-------------------

Define macros, that can represent a constant or a method.

    <c_macros
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ is_method = "0 | 1"  ("0") ]
        >
        <c_implementation>, optional
    </c_macros>

The c_macros item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.   

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

is_method:
    The is_method attribute is optional. Its default value is "0". It can
    take one of the following values:                                    

Value: Meaning:
0: Macros is a constant.
1: Macros is a method.


The 'c_implementation' item
---------------------------

Defines method or macros implementation.

    <c_implementation>


