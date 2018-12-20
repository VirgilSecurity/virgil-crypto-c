Defines different implementations that is based on the same underlying
library.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <implementor name [is_default]>
       <implementation name [c_prefix] [full_uid] [visibility] [scope] [uid]>
          <context>
             <require [scope] [project] [library] [module] [header] [feature] [interface] [class]
                  [impl] [enum]>
                <alternative [scope] [project] [library] [module] [header] [feature] [interface] [class]
                     [impl] [enum]/>
             </require>
             <property is_reference name [full_uid] [library] [access] [type] [class] [enum] [callback]
                  [interface] [api] [impl] [size] [uid] [require_definition]
                  [project] [bits]>
                <string [access] [length] [length_constant]/>
                <array [access] [length] [length_constant]/>
             </property>
          </context>
          <interface name>
             <constant name [c_prefix] [of_class] [uid] [full_uid] [feature] [definition] [value]/>
          </interface>
          <dependency name [library] [project] [interface] [api] [class] [impl] [type_name] [has_observers]/>
          <require .../>
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
1: Implementor is default, so it's name will not be prefixed to types and functions.


The 'implementation' item
-------------------------

Defines set of the implemented interfaces in a one module.

    <implementation
        name = "..."
      [ c_prefix = "..." ]
      [ full_uid = "..." ]
      [ visibility = "public | private"  ("public") ]
      [ scope = "public | private | internal"  ("public") ]
      [ uid = "..." ]
        >
        <context>, optional
        <interface>, 1 or more
        <dependency>
        <require>
    </implementation>

The implementation item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

scope:
    Defines component visibility within scope. This attribute must not be
    inherited. Note, scope attribute can be used for components, that can not
    be defined in terms of 'declaration' and 'definition'. The scope
    attribute is optional. Its default value is "public". It can take one of
    the following values:

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible for outside world via private interface.
internal: Component is visible only within library or a specific source file.

name:
    Implementation name. The name attribute is required.


The 'context' item
------------------

Defines specific underlying implementation context.

    <context>
        <require>
        <property>
    </context>



The 'require' item
------------------

Base attributes for require. Defines dependency to: module, header,
feature.

    <require
      [ scope = "public | private | context"  ("public") ]
      [ project = "..." ]
      [ library = "..." ]
      [ module = "..." ]
      [ header = "..." ]
      [ feature = "..." ]
      [ interface = "..." ]
      [ class = "..." ]
      [ impl = "..." ]
      [ enum = "..." ]
        >
        <alternative>
    </require>

The require item can have these attributes:

scope:
    Defines scope for required component. The scope attribute is optional.
    Its default value is "public". It can take one of the following values:

Value: Meaning:
public: Required component is visible for outside world.
private: Required component can be accessed within specific source file only.
context: Component is required by context, so it is visible if context is visible.

project:
    Defines project name that component refers to. The project attribute is
    optional.

library:
    Defines library name that component refers to. The library attribute is
    optional.

module:
    Required module name. The module attribute is optional.

header:
    Required header file name. The header attribute is optional.

feature:
    Required feature name. The feature attribute is optional.

interface:
    Required interface name. The interface attribute is optional.

class:
    Required class name. The class attribute is optional.

impl:
    Required implementation name. The impl attribute is optional.

enum:
    Required implementation name. The enum attribute is optional.


The 'alternative' item
----------------------

Base attributes for require. Define alternative requirements that can be
used, and in fact replace each other.

    <alternative
      [ scope = "public | private | context"  ("public") ]
      [ project = "..." ]
      [ library = "..." ]
      [ module = "..." ]
      [ header = "..." ]
      [ feature = "..." ]
      [ interface = "..." ]
      [ class = "..." ]
      [ impl = "..." ]
      [ enum = "..." ]
        />

The alternative item can have these attributes:

scope:
    Defines scope for required component. The scope attribute is optional.
    Its default value is "public". It can take one of the following values:

Value: Meaning:
public: Required component is visible for outside world.
private: Required component can be accessed within specific source file only.
context: Component is required by context, so it is visible if context is visible.

project:
    Defines project name that component refers to. The project attribute is
    optional.

library:
    Defines library name that component refers to. The library attribute is
    optional.

module:
    Required module name. The module attribute is optional.

header:
    Required header file name. The header attribute is optional.

feature:
    Required feature name. The feature attribute is optional.

interface:
    Required interface name. The interface attribute is optional.

class:
    Required class name. The class attribute is optional.

impl:
    Required implementation name. The impl attribute is optional.

enum:
    Required implementation name. The enum attribute is optional.


The 'property' item
-------------------

Defines attributes that related to the instance type. Defines struct
property.

    <property
        is_reference = "0 | 1"
        name = "..."
      [ full_uid = "..." ]
      [ library = "..." ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | unsigned | size | byte | string | char | varargs" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ interface = "..." ]
      [ api = "..." ]
      [ impl = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ uid = "..." ]
      [ require_definition = "public | private" ]
      [ project = "..." ]
      [ bits = "..." ]
        >
        <string>, optional
        <array>, optional
    </property>

The property item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

project:
    Defines project name that component refers to. The project attribute is
    optional.

library:
    Defines library name that component refers to. The library attribute is
    optional.

access:
    Defines access rights to the instance and/or array of instances. The
    access attribute is optional. It can take one of the following values:

Value: Meaning:
readonly: Value of the given type is can be modified.
writeonly: Value of the given type will be modified.
readwrite: Value of the given type can be read and then modified.
disown: Ownership of the given class object is transferred. If object is passed via argument to method, then client can not use object after method return. If object is returned from method, then client is responsible for object destruction. Note, primitive type can not be disowned.

type:
    Defines instance primitive type. The type attribute is optional. It can
    take one of the following values:

Value: Meaning:
nothing: The same as a C void type.
boolean: True / False type.
integer: Signed integral type.
unsigned: Unsigned integral type.
size: Unsigned integral type for size definition.
byte: Unsigned 8-bit integral type.
string: Shortcut for the char array.
char: Type for a character.
varargs: Type for variadic arguments.

class:
    Defines instance class. Possible values are: * any - Any class or type. *
    data - Special class "data" that is used as an input byte array. * buffer
    - Special class "buffer" that is used as an output byte array. * impl -
    Universal implementation class. * self - Allowed within high-level
    entities, i.e. class, implementation, to refer the context type. If value
    differs from the listed above then next algorithm applied: 1. If value in
    a format .(uid), then it treated as a reference to the in-project class
    and will be substituted during context resolution step. 2. If attribute
    'library' is defined, then it treated as third-party library class and
    will be used as-is. 3. Any other value will be treated as cross-project
    class name and will be converted to the .(uid). The class attribute is
    optional.

enum:
    Defines enumeration type. 1. If value in a format .(uid), then it treated
    as a reference to the in-project enumeration and will be substituted
    during context resolution step. 2. If attribute 'library' is defined,
    then it treated as third-party library class and will be used as-is. 3.
    Any other value will be treated as cross-project class name and will be
    converted to the .(uid). The enum attribute is optional.

callback:
    Defines instance as a callback. 1. If value in a format .(uid), then it
    treated as a reference to the in-project callback and will be substituted
    during context resolution step. 2. If attribute 'library' is defined,
    then it treated as third-party library class and will be used as-is. 3.
    Any other value will be treated as cross-project class name and will be
    converted to the .(uid). The callback attribute is optional.

interface:
    Defines instance as implementation of specific interface. The interface
    attribute is optional.

api:
    Defines instance as specific interface api. The api attribute is
    optional.

impl:
    Defines instance as specific implementation. The impl attribute is
    optional.

size:
    Define size of the primitive type or enum in bytes. The size attribute is
    optional. It can take one of the following values:

Value: Meaning:
1: Size of the type is one byte.
2: Size of the type is two bytes.
4: Size of the type is three bytes.
8: Size of the type is four bytes.

is_reference:
    Defines whether instance is a 'reference' instance. For 'type' - default
    is '0'. For 'enum' - default is '0'. For 'callback' - default is '0'. For
    'class' - default is '1'. The is_reference attribute is required. It can
    take one of the following values:

Value: Meaning:
0: Instance is not a reference.
1: Instance is a reference to the other instance.

require_definition:
    Defines if instance requires type definition. The require_definition
    attribute is optional. It can take one of the following values:

Value: Meaning:
public: Instance type definition is used within private scope.
private: Instance type definition is used within private scope.

name:
    Property name. The name attribute is required.

bits:
    Define number of bits occupied by the property with integral type. The
    bits attribute is optional.


The 'string' item
-----------------

Defines restrictions to the special class 'string'.

    <string
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ length = "null_terminated | given | fixed | derived"  ("null_terminated") ]
      [ length_constant = "..." ]
        />

The string item can have these attributes:

access:
    Defines access rights to the instance and/or array of instances. The
    access attribute is optional. It can take one of the following values:

Value: Meaning:
readonly: Value of the given type is can be modified.
writeonly: Value of the given type will be modified.
readwrite: Value of the given type can be read and then modified.
disown: Ownership of the given class object is transferred. If object is passed via argument to method, then client can not use object after method return. If object is returned from method, then client is responsible for object destruction. Note, primitive type can not be disowned.

length:
    Defines string length. The length attribute is optional. Its default
    value is "null_terminated". It can take one of the following values:

Value: Meaning:
null_terminated: String length is defined by distance from the first character up to the termination symbol (aka '\0').
given: String length is given from the client.
fixed: String length is known at compile time, so it can be substituted automatically.
derived: String length can be statically derived during string initialization.

length_constant:
    For fixed size string it defines number of characters as integral
    constant. The length_constant attribute is optional.


The 'array' item
----------------

Turn parent instance to the array of instances.

    <array
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ length = "null_terminated | given | known | fixed | derived" ]
      [ length_constant = "..." ]
        />

The array item can have these attributes:

access:
    Defines access rights to the instance and/or array of instances. The
    access attribute is optional. It can take one of the following values:

Value: Meaning:
readonly: Value of the given type is can be modified.
writeonly: Value of the given type will be modified.
readwrite: Value of the given type can be read and then modified.
disown: Ownership of the given class object is transferred. If object is passed via argument to method, then client can not use object after method return. If object is returned from method, then client is responsible for object destruction. Note, primitive type can not be disowned.

length:
    Defines array length. The length attribute is optional. It can take one
    of the following values:

Value: Meaning:
null_terminated: Array length is defined by distance from the first element up to the empty element (aka NULL).
given: Array length is defined from the client.
known: Array length is defined from the client. Also client can obtained this value from a constant or a method.
fixed: Array length is known at compile time, so it can be substituted automatically.
derived: Array length can be statically derived during array initialization.

length_constant:
    For fixed size array it defines number of elements as integral constant.
    The length_constant attribute is optional.


The 'interface' item
--------------------

Provide information about implemented interface.

    <interface
        name = "..."
        >
        <constant>
    </interface>

The interface item has this single attribute:

name:
    Name of the implemented interface. The name attribute is required.


The 'constant' item
-------------------

Groups common attributes for the component. Defines integral constant.

    <constant
        name = "..."
      [ c_prefix = "..." ]
      [ of_class = "..." ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ feature = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ value = "..." ]
        />

The constant item can have these attributes:

definition:
    Defines where component will be defined. This attribute must not be
    inherited. The definition attribute is optional. Its default value is
    "private". It can take one of the following values:

Value: Meaning:
public: Component definition is visible for outside world.
private: Component definition is hidden in a correspond source file.
external: Component definition is located somewhere.

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.

of_class:
    Defines class name that a component belongs to. This attributes is used
    for inner components name resolution. The of_class attribute is optional.

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

full_uid:
    Unique component identifier represents name that uniquely identifies
    component within projects hierarchy. The full_uid attribute is optional.

feature:
    In-project feature name that is implemented. This attribute is used for
    feature-based compilation. The feature attribute is optional.

name:
    Constant name. The name attribute is required.

value:
    Constant value. Optional for enumerated constant. The value attribute is
    optional.


The 'dependency' item
---------------------

Defines dependency to interface or class.

    <dependency
        name = "..."
      [ library = "..." ]
      [ project = "..." ]
      [ interface = "..." ]
      [ api = "..." ]
      [ class = "..." ]
      [ impl = "..." ]
      [ type_name = "..." ]
      [ has_observers = "0 | 1"  ("0") ]
        />

The dependency item can have these attributes:

project:
    Defines project name that component refers to. The project attribute is
    optional.

library:
    Defines library name that component refers to. The library attribute is
    optional.

name:
    Dependency name - used for properties and methods names. The name
    attribute is required.

interface:
    Defines name of the interface depends on. Dependency is taken as
    implementation object. The interface attribute is optional.

api:
    Defines name of the interface depends on. Dependency is taken as
    interface api object. The api attribute is optional.

class:
    Defines name of the class depends on. Dependency is taken as class
    context object. The class attribute is optional.

impl:
    Defines name of the implementation depends on. Dependency is taken as
    specific implementation object. The impl attribute is optional.

type_name:
    This is auto-resolve attribute! It is equal to the one of the attributes:
    {interface, api, class}. The type_name attribute is optional.

has_observers:
    Allows to add observer methods for the dependency. The has_observers
    attribute is optional. Its default value is "0". It can take one of the
    following values:

Value: Meaning:
0: Property is not observed.
1: Property is observed so methods "did_setup" and "did_release" must be generated.

