Defines different implementations that is based on the same underlying
library.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <implementor name [is_default]>
       <implementation name [project]>
          <context>
             <require [scope] [project] [library] [module] [header] [feature] [interface] [class]>
                <alternative [scope] [project] [library] [module] [header] [feature] [interface] [class]/>
             </require>
             <property is_reference name [type] [class] [enum] [callback] [size] [uid] [access] [bits]>
                <string [access] [length]/>
                <array [access] [length] [length_constant]/>
             </property>
          </context>
          <interface name>
             <constant name [c_prefix] [of_class] [uid] [feature] [definition] [value]/>
          </interface>
          <dependency name interface [type]/>
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
1: Implementor is not default, so it's name will will be prefixed as usual.


The 'implementation' item
-------------------------

Defines set of the implemented interfaces in a one module.

    <implementation
        name = "..."
      [ project = "..." ]
        >
        <context>, optional
        <interface>, 1 or more
        <dependency>
        <require>
    </implementation>

The implementation item can have these attributes:

project:
    Parent project name. The project attribute is optional.

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

Defines whom component belongs to. Base attributes for require. Defines
dependency to: module, header, feature.

    <require
      [ scope = "public | private | internal"  ("public") ]
      [ project = "..." ]
      [ library = "..." ]
      [ module = "..." ]
      [ header = "..." ]
      [ feature = "..." ]
      [ interface = "..." ]
      [ class = "..." ]
        >
        <alternative>
    </require>

The require item can have these attributes:

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

project:
    Defines project name that component belongs to. The project attribute is
    optional.

library:
    Defines libary name that component belongs to. The library attribute is
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


The 'alternative' item
----------------------

Defines whom component belongs to. Base attributes for require. Define
alternative requirements that can be used, and in fact replace each other.

    <alternative
      [ scope = "public | private | internal"  ("public") ]
      [ project = "..." ]
      [ library = "..." ]
      [ module = "..." ]
      [ header = "..." ]
      [ feature = "..." ]
      [ interface = "..." ]
      [ class = "..." ]
        />

The alternative item can have these attributes:

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

project:
    Defines project name that component belongs to. The project attribute is
    optional.

library:
    Defines libary name that component belongs to. The library attribute is
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


The 'property' item
-------------------

Defines attributes that related to the instance type. Defines struct
property.

    <property
        is_reference = "0 | 1"
        name = "..."
      [ type = "nothing | boolean | integer | size | byte | data | string | error" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ uid = "..." ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ bits = "..." ]
        >
        <string>, optional
        <array>, optional
    </property>

The property item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

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
size: Unsigned integral type for size definition.
byte: Unsigned 8-bit integral type.
data: Shortcut for the byte array.
string: Shortcut for the char array.
error: Type for error codes.

class:
    Defines instance class. Possible values are: * any - Any class or type. *
    data - Special class "data" that is used as an input byte array. * buffer
    - Special class "buffer" that is used as an output byte array. * impl -
    Universal implementation class. If value differs from the listed above
    then next algorithm applied: 1. If value in a format .(uid), then it
    treated as a reference to the in-project class and will be substituted
    during context resolution step. 2. Any other value will be used as-is. So
    one third party type can be used. The class attribute is optional.

enum:
    Defines enumeration type. 1. If value in a format .(uid), then it treated
    as a reference to the in-project enumeration and will be substituted
    during context resolution step. 2. Any other value will be used as-is. So
    one third party type can be used. The enum attribute is optional.

callback:
    Defines instance as a callback. 1. If value in a format .(uid), then it
    treated as a reference to the in-project callback and will be substituted
    during context resolution step. 2. Any other value will be used as-is. So
    one third party type can be used. The callback attribute is optional.

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
0: Instance is not a refernce.
1: Instance is a reference to the other instance.

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

Defines implementation dependency.

    <dependency
        name = "..."
        interface = "..."
      [ type = "api | impl"  ("api") ]
        />

The dependency item can have these attributes:

name:
    Dependency name - used for properties and methods names. The name
    attribute is required.

interface:
    Dependency interface - used for type deduction and includes. The
    interface attribute is required.

type:
    Dependency type. The type attribute is optional. Its default value is
    "api". It can take one of the following values:

Value: Meaning:
api: Dependency is an interface API object.
impl: Dependency is an implementation object.

