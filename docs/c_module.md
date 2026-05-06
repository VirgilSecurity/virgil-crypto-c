Base model for C language code generation.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <c_module output_source_file once_guard id name header_file source_file output_header_file
         [of_class] [scope] [has_cmakedefine]>
       <c_include file [feature] [scope] [is_system]/>
       <c_alias type name [declaration]/>
       <c_enum [feature] [uid] [full_uid] [definition] [declaration] [visibility] [name]>
          <c_constant name [uid] [full_uid] [definition] [feature] [value]/>
       </c_enum>
       <c_struct name [feature] [declaration] [uid] [full_uid] [definition]>
          <c_property type type_is name [array] [string] [length] [is_const_type] [is_const_pointer]
               [is_const_array] [is_const_string] [is_const_reference] [require_definition]
               [feature] [uid] [full_uid] [accessed_by] [bits]/>
       </c_struct>
       <c_variable type type_is name [array] [accessed_by] [length] [is_const_type] [is_const_pointer]
            [is_const_array] [is_const_string] [is_const_reference] [require_definition]
            [feature] [definition] [declaration] [visibility] [uid] [full_uid]
            [string]>
          <c_value value>
             <c_cast type type_is [accessed_by] [array] [string] [length] [is_const_type] [is_const_pointer]
                  [is_const_array] [is_const_string] [is_const_reference] [require_definition]/>
          </c_value>
          <c_modifier [value]/>
       </c_variable>
       <c_method name [feature] [full_uid] [definition] [declaration] [visibility] [uid]>
          <c_modifier .../>
          <c_return type type_is [accessed_by] [array] [string] [length] [is_const_type] [is_const_pointer]
               [is_const_array] [is_const_string] [is_const_reference] [require_definition]/>
          <c_argument type type_is name [accessed_by] [string] [length] [is_const_type] [is_const_pointer]
               [is_const_array] [is_const_string] [is_const_reference] [require_definition]
               [uid] [full_uid] [array]/>
          <c_precondition [position]/>
          <c_attribute [value]/>
       </c_method>
       <c_callback name [uid] [full_uid] [declaration]>
          <c_return .../>
          <c_argument .../>
       </c_callback>
       <c_macros [feature] [definition] [uid] [full_uid] [is_method]>
          <c_code/>
       </c_macros>
       <c_macroses [definition]>
          <c_macros .../>
          <c_code .../>
       </c_macroses>
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
        id = "..."
        name = "..."
        header_file = "..."
        source_file = "..."
        output_header_file = "..."
      [ of_class = "..." ]
      [ scope = "public | private | internal"  ("public") ]
      [ has_cmakedefine = "0 | 1"  ("0") ]
        >
        <c_include>
        <c_alias>
        <c_enum>
        <c_struct>
        <c_variable>
        <c_method>
        <c_callback>
        <c_macros>
        <c_macroses>
    </c_module>

The c_module item can have these attributes:

of_class:
    Defines class name that a component belongs to. This attributes is used
    for inner components name resolution. The of_class attribute is optional.

scope:
    Defines component visibility within scope. This attribute must not be
    inherited. Note, scope attribute can be used for components, that can not
    be defined in terms of 'declaration' and 'definition'. The scope
    attribute is optional. Its default value is "public". It can take one of
    the following values:

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible for outside world via private interface.
internal: Component is visible only within library.

id:
    Short module name. The id attribute is required.

name:
    Complete module name. The name attribute is required.

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

has_cmakedefine:
    Defines that module must be configured with CMake configure_file()
    command. The has_cmakedefine attribute is optional. Its default value is
    "0". It can take one of the following values:

Value: Meaning:
0: Module does not contain CMake variables and #cmakedefine instructions.
1: Module contains CMake variables and/or #cmakedefine instructions.


The 'c_include' item
--------------------

Defines feature name.

    <c_include
        file = "..."
      [ feature = "..." ]
      [ scope = "public | private | internal"  ("public") ]
      [ is_system = "0 | 1"  ("0") ]
        />

The c_include item can have these attributes:

scope:
    Defines component visibility within scope. This attribute must not be
    inherited. Note, scope attribute can be used for components, that can not
    be defined in terms of 'declaration' and 'definition'. The scope
    attribute is optional. Its default value is "public". It can take one of
    the following values:

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible for outside world via private interface.
internal: Component is visible only within library.

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

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
        type = "..."
        name = "..."
      [ declaration = "public | private | external"  ("public") ]
        />

The c_alias item can have these attributes:

declaration:
    Defines where component will be declared. This attribute must not be
    inherited. The declaration attribute is optional. Its default value is
    "public". It can take one of the following values:

Value: Meaning:
public: Component declaration is visible for outside world.
private: Component declaration is hidden in a correspond source file.
external: Component declaration is located somewhere.

name:
    Alias name. The name attribute is required.

type:
    Alias type. The type attribute is required.


The 'c_enum' item
-----------------

Defines feature name. Defines enumeration type.

    <c_enum
      [ feature = "..." ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ declaration = "public | private | external"  ("public") ]
      [ visibility = "public | private"  ("public") ]
      [ name = "..." ]
        >
        <c_constant>, 1 or more
    </c_enum>

The c_enum item can have these attributes:

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

declaration:
    Defines where component will be declared. This attribute must not be
    inherited. The declaration attribute is optional. Its default value is
    "public". It can take one of the following values:

Value: Meaning:
public: Component declaration is visible for outside world.
private: Component declaration is hidden in a correspond source file.
external: Component declaration is located somewhere.

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

name:
    Enumeration name. Can be omitted if it is used to define named constants.
    The name attribute is optional.


The 'c_constant' item
---------------------

Defines feature name. Defines integral constant.

    <c_constant
        name = "..."
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ feature = "..." ]
      [ value = "..." ]
        />

The c_constant item can have these attributes:

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

name:
    Constant name. The name attribute is required.

value:
    Constant value. The value attribute is optional.


The 'c_struct' item
-------------------

Defines feature name. Define structure type.

    <c_struct
        name = "..."
      [ feature = "..." ]
      [ declaration = "public | private | external"  ("public") ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ definition = "public | private | external"  ("private") ]
        >
        <c_property>, 1 or more
    </c_struct>

The c_struct item can have these attributes:

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

declaration:
    Defines where component will be declared. This attribute must not be
    inherited. The declaration attribute is optional. Its default value is
    "public". It can take one of the following values:

Value: Meaning:
public: Component declaration is visible for outside world.
private: Component declaration is hidden in a correspond source file.
external: Component declaration is located somewhere.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

name:
    Structure name. The name attribute is required.


The 'c_property' item
---------------------

Defines a type of outer component. Defines feature name. Define property of
the structure type.

    <c_property
        type = "..."
        type_is = "primitive | class | callback | any"
        name = "..."
      [ array = "null_terminated | given | fixed | derived" ]
      [ string = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_string = "..." ]
      [ is_const_reference = "..." ]
      [ require_definition = "public | private" ]
      [ feature = "..." ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ accessed_by = "value | pointer | reference"  ("value") ]
      [ bits = "..." ]
        />

The c_property item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

type_is:
    Define type kind. The type_is attribute is required. It can take one of
    the following values:

Value: Meaning:
primitive: Type is primitive.
class: Type is class.
callback: Type is class.
any: Any type.

accessed_by:
    Defines how instance is accessed. The accessed_by attribute is optional.
    Its default value is "value". It can take one of the following values:

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

string:
    Defines string length type. If given, parent instance becomes a string.
    The string attribute is optional. It can take one of the following
    values:

Value: Meaning:
null_terminated: Null-terminated string, 'char *'
given: String whith a given length, i.e. 'char *'.
fixed: String with a Fixed length, i.e. 'char [32]'.
derived: String with a derived length, i.e. 'char []'.

length:
    Defines length constant for the fixed array or fixed string. Note, this
    attribute is used where appropriate. The length attribute is optional.

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.

is_const_array:
    Defines array constness. The is_const_array attribute is optional.

is_const_string:
    Defines string constness. The is_const_string attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.

require_definition:
    Defines if instance requires type definition. The require_definition
    attribute is optional. It can take one of the following values:

Value: Meaning:
public: Instance type definition is used within private scope.
private: Instance type definition is used within private scope.

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

name:
    Property name. The name attribute is required.

bits:
    Define number of bits occupied by the property with integral type. The
    bits attribute is optional.


The 'c_variable' item
---------------------

Defines a type of outer component. Defines feature name. Define global
variable.

    <c_variable
        type = "..."
        type_is = "primitive | class | callback | any"
        name = "..."
      [ array = "null_terminated | given | fixed | derived" ]
      [ accessed_by = "value | pointer | reference"  ("value") ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_string = "..." ]
      [ is_const_reference = "..." ]
      [ require_definition = "public | private" ]
      [ feature = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ declaration = "public | private | external"  ("public") ]
      [ visibility = "public | private"  ("public") ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ string = "null_terminated | given | fixed | derived" ]
        >
        <c_value>, 1 or more
        <c_modifier>
    </c_variable>

The c_variable item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

type_is:
    Define type kind. The type_is attribute is required. It can take one of
    the following values:

Value: Meaning:
primitive: Type is primitive.
class: Type is class.
callback: Type is class.
any: Any type.

accessed_by:
    Defines how instance is accessed. The accessed_by attribute is optional.
    Its default value is "value". It can take one of the following values:

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

string:
    Defines string length type. If given, parent instance becomes a string.
    The string attribute is optional. It can take one of the following
    values:

Value: Meaning:
null_terminated: Null-terminated string, 'char *'
given: String whith a given length, i.e. 'char *'.
fixed: String with a Fixed length, i.e. 'char [32]'.
derived: String with a derived length, i.e. 'char []'.

length:
    Defines length constant for the fixed array or fixed string. Note, this
    attribute is used where appropriate. The length attribute is optional.

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.

is_const_array:
    Defines array constness. The is_const_array attribute is optional.

is_const_string:
    Defines string constness. The is_const_string attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.

require_definition:
    Defines if instance requires type definition. The require_definition
    attribute is optional. It can take one of the following values:

Value: Meaning:
public: Instance type definition is used within private scope.
private: Instance type definition is used within private scope.

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

declaration:
    Defines where component will be declared. This attribute must not be
    inherited. The declaration attribute is optional. Its default value is
    "public". It can take one of the following values:

Value: Meaning:
public: Component declaration is visible for outside world.
private: Component declaration is hidden in a correspond source file.
external: Component declaration is located somewhere.

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

name:
    Object name. The name attribute is required.


The 'c_value' item
------------------

Defines specific variable value.

    <c_value
        value = "..."
        >
        <c_cast>, optional
    </c_value>

The c_value item has this single attribute:

value:
    Specific value. The value attribute is required.


The 'c_cast' item
-----------------

Defines a type of outer component. Cast parent instance type to the type
defined in this entity.

    <c_cast
        type = "..."
        type_is = "primitive | class | callback | any"
      [ accessed_by = "value | pointer | reference"  ("value") ]
      [ array = "null_terminated | given | fixed | derived" ]
      [ string = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_string = "..." ]
      [ is_const_reference = "..." ]
      [ require_definition = "public | private" ]
        />

The c_cast item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

type_is:
    Define type kind. The type_is attribute is required. It can take one of
    the following values:

Value: Meaning:
primitive: Type is primitive.
class: Type is class.
callback: Type is class.
any: Any type.

accessed_by:
    Defines how instance is accessed. The accessed_by attribute is optional.
    Its default value is "value". It can take one of the following values:

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

string:
    Defines string length type. If given, parent instance becomes a string.
    The string attribute is optional. It can take one of the following
    values:

Value: Meaning:
null_terminated: Null-terminated string, 'char *'
given: String whith a given length, i.e. 'char *'.
fixed: String with a Fixed length, i.e. 'char [32]'.
derived: String with a derived length, i.e. 'char []'.

length:
    Defines length constant for the fixed array or fixed string. Note, this
    attribute is used where appropriate. The length attribute is optional.

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.

is_const_array:
    Defines array constness. The is_const_array attribute is optional.

is_const_string:
    Defines string constness. The is_const_string attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.

require_definition:
    Defines if instance requires type definition. The require_definition
    attribute is optional. It can take one of the following values:

Value: Meaning:
public: Instance type definition is used within private scope.
private: Instance type definition is used within private scope.


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

Defines feature name. Define method signature and implementation
(optional).

    <c_method
        name = "..."
      [ feature = "..." ]
      [ full_uid = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ declaration = "public | private | external"  ("public") ]
      [ visibility = "public | private"  ("public") ]
      [ uid = "..." ]
        >
        <c_modifier>
        <c_return>, optional
        <c_argument>
        <c_precondition>
        <c_attribute>
    </c_method>

The c_method item can have these attributes:

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

declaration:
    Defines where component will be declared. This attribute must not be
    inherited. The declaration attribute is optional. Its default value is
    "public". It can take one of the following values:

Value: Meaning:
public: Component declaration is visible for outside world.
private: Component declaration is hidden in a correspond source file.
external: Component declaration is located somewhere.

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

name:
    Method name. The name attribute is required.


The 'c_return' item
-------------------

Defines a type of outer component. Defines return type.

    <c_return
        type = "..."
        type_is = "primitive | class | callback | any"
      [ accessed_by = "value | pointer | reference"  ("value") ]
      [ array = "null_terminated | given | fixed | derived" ]
      [ string = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_string = "..." ]
      [ is_const_reference = "..." ]
      [ require_definition = "public | private" ]
        />

The c_return item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

type_is:
    Define type kind. The type_is attribute is required. It can take one of
    the following values:

Value: Meaning:
primitive: Type is primitive.
class: Type is class.
callback: Type is class.
any: Any type.

accessed_by:
    Defines how instance is accessed. The accessed_by attribute is optional.
    Its default value is "value". It can take one of the following values:

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

string:
    Defines string length type. If given, parent instance becomes a string.
    The string attribute is optional. It can take one of the following
    values:

Value: Meaning:
null_terminated: Null-terminated string, 'char *'
given: String whith a given length, i.e. 'char *'.
fixed: String with a Fixed length, i.e. 'char [32]'.
derived: String with a derived length, i.e. 'char []'.

length:
    Defines length constant for the fixed array or fixed string. Note, this
    attribute is used where appropriate. The length attribute is optional.

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.

is_const_array:
    Defines array constness. The is_const_array attribute is optional.

is_const_string:
    Defines string constness. The is_const_string attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.

require_definition:
    Defines if instance requires type definition. The require_definition
    attribute is optional. It can take one of the following values:

Value: Meaning:
public: Instance type definition is used within private scope.
private: Instance type definition is used within private scope.


The 'c_argument' item
---------------------

Defines a type of outer component. Defines method or callback argument.

    <c_argument
        type = "..."
        type_is = "primitive | class | callback | any"
        name = "..."
      [ accessed_by = "value | pointer | reference"  ("value") ]
      [ string = "null_terminated | given | fixed | derived" ]
      [ length = "..." ]
      [ is_const_type = "..." ]
      [ is_const_pointer = "..." ]
      [ is_const_array = "..." ]
      [ is_const_string = "..." ]
      [ is_const_reference = "..." ]
      [ require_definition = "public | private" ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ array = "null_terminated | given | fixed | derived" ]
        />

The c_argument item can have these attributes:

type:
    Type without any modifiers. The type attribute is required.

type_is:
    Define type kind. The type_is attribute is required. It can take one of
    the following values:

Value: Meaning:
primitive: Type is primitive.
class: Type is class.
callback: Type is class.
any: Any type.

accessed_by:
    Defines how instance is accessed. The accessed_by attribute is optional.
    Its default value is "value". It can take one of the following values:

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

string:
    Defines string length type. If given, parent instance becomes a string.
    The string attribute is optional. It can take one of the following
    values:

Value: Meaning:
null_terminated: Null-terminated string, 'char *'
given: String whith a given length, i.e. 'char *'.
fixed: String with a Fixed length, i.e. 'char [32]'.
derived: String with a derived length, i.e. 'char []'.

length:
    Defines length constant for the fixed array or fixed string. Note, this
    attribute is used where appropriate. The length attribute is optional.

is_const_type:
    Defines type constness. The is_const_type attribute is optional.

is_const_pointer:
    Defines pointer constness. TODO: Define if this attribute is useless. The
    is_const_pointer attribute is optional.

is_const_array:
    Defines array constness. The is_const_array attribute is optional.

is_const_string:
    Defines string constness. The is_const_string attribute is optional.

is_const_reference:
    Defines reference constness. TODO: Define if this attribute is useless.
    The is_const_reference attribute is optional.

require_definition:
    Defines if instance requires type definition. The require_definition
    attribute is optional. It can take one of the following values:

Value: Meaning:
public: Instance type definition is used within private scope.
private: Instance type definition is used within private scope.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

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


The 'c_attribute' item
----------------------

Defines method attribute: __attribute__ (...).

    <c_attribute
      [ value = "..." ]
        />

The c_attribute item has this single attribute:

value:
    Attribute itself. The value attribute is optional.


The 'c_callback' item
---------------------

Define callback type.

    <c_callback
        name = "..."
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ declaration = "public | private | external"  ("public") ]
        >
        <c_return>, optional
        <c_argument>
    </c_callback>

The c_callback item can have these attributes:

declaration:
    Defines where component will be declared. This attribute must not be
    inherited. The declaration attribute is optional. Its default value is
    "public". It can take one of the following values:

Value: Meaning:
public: Component declaration is visible for outside world.
private: Component declaration is hidden in a correspond source file.
external: Component declaration is located somewhere.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

name:
    Method name. The name attribute is required.


The 'c_macros' item
-------------------

Defines feature name. Define macros, that can represent a constant or a
method.

    <c_macros
      [ feature = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ is_method = "0 | 1"  ("0") ]
        >
        <c_code>, optional
    </c_macros>

The c_macros item can have these attributes:

feature:
    Defines feature name. Component that holds this attribute should be
    wrapped with #if <feature> #endif macros. The feature attribute is
    optional.

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

is_method:
    The is_method attribute is optional. Its default value is "0". It can
    take one of the following values:

Value: Meaning:
0: Macros is a constant.
1: Macros is a method.


The 'c_code' item
-----------------

Defines method or macros implementation.

    <c_code>



The 'c_macroses' item
---------------------

Define set of macroses in the one implemenatation.

    <c_macroses
      [ definition = "public | private | external"  ("private") ]
        >
        <c_macros>, 1 or more
        <c_code>, optional
    </c_macroses>

The c_macroses item has this single attribute:

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

