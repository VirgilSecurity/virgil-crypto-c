Defines C class interface as a set of constants and methods.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <interface [c_namespace] [uid] [full_uid] [visibility] [scope]>
       <constant name [c_namespace] [name_prefix] [uid] [full_uid] [feature] [definition] [value]/>
       <method name [definition] [visibility] [c_namespace] [name_prefix] [uid] [full_uid] [feature]
            [declaration] [is_static]>
          <return is_reference [project] [access] [type] [class] [enum] [callback] [interface]
               [api] [impl] [size] [library] [require_definition]>
             <string [access] [length] [length_constant]/>
             <array [access] [length] [length_constant]/>
          </return>
          <argument name is_reference [project] [uid] [access] [type] [class] [enum] [callback]
               [interface] [api] [impl] [size] [full_uid] [require_definition]
               [library]>
             <string .../>
             <array .../>
          </argument>
          <variable name is_reference [access] [type] [project] [enum] [callback] [interface] [api]
               [impl] [size] [library] [require_definition] [definition] [declaration]
               [visibility] [c_namespace] [name_prefix] [uid] [full_uid] [feature]
               [class]>
             <value is_reference value [library] [type] [class] [enum] [callback] [interface] [api]
                  [impl] [size] [project] [require_definition] [access]>
                <cast is_reference [project] [access] [type] [class] [enum] [callback] [interface]
                     [api] [impl] [size] [library] [require_definition]>
                   <string .../>
                   <array .../>
                </cast>
                <string .../>
                <array .../>
             </value>
             <string .../>
             <array .../>
          </variable>
          <code [lang] [type]/>
       </method>
       <inherit interface/>
    </interface>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'interface' item
--------------------

Defines C class interface as a set of constants and methods.

    <interface
      [ c_namespace = "..." ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ visibility = "public | private"  ("public") ]
      [ scope = "public | private | internal"  ("public") ]
        >
        <constant>
        <method>
        <inherit>
    </interface>

The interface item can have these attributes:

c_namespace:
    Prefix that is used for C name resolution. The c_namespace attribute is
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


The 'constant' item
-------------------

Groups common attributes for the component. Defines integral constant.

    <constant
        name = "..."
      [ c_namespace = "..." ]
      [ name_prefix = "..." ]
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

c_namespace:
    Prefix that is used for C name resolution. The c_namespace attribute is
    optional.

name_prefix:
    Defines class name that a component belongs to. This attributes is used
    for inner components name resolution. The name_prefix attribute is optional.

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


The 'method' item
-----------------

Groups common attributes for the component. Defines the method signature
and optionally implementation.

    <method
        name = "..."
      [ definition = "public | private | external"  ("private") ]
      [ visibility = "public | private"  ("public") ]
      [ c_namespace = "..." ]
      [ name_prefix = "..." ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ feature = "..." ]
      [ declaration = "public | private | external"  ("public") ]
      [ is_static = "0 | 1"  ("0") ]
        >
        <return>, optional
        <argument>
        <variable>
        <code>, optional
    </method>

The method item can have these attributes:

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

c_namespace:
    Prefix that is used for C name resolution. The c_namespace attribute is
    optional.

name_prefix:
    Defines class name that a component belongs to. This attributes is used
    for inner components name resolution. The name_prefix attribute is optional.

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
    Method name. The name attribute is required.

is_static:
    Defines that method is a class-level method. The is_static attribute is
    optional. Its default value is "0". It can take one of the following
    values:

Value: Meaning:
0: Method is a class-level method.
1: Method is an object-level method.


The 'return' item
-----------------

Defines attributes that related to the instance type. Defines return type.

    <return
        is_reference = "0 | 1"
      [ project = "..." ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | unsigned | size | byte | string | char | varargs" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ interface = "..." ]
      [ api = "..." ]
      [ impl = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ library = "..." ]
      [ require_definition = "public | private" ]
        >
        <string>, optional
        <array>, optional
    </return>

The return item can have these attributes:

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


The 'argument' item
-------------------

Defines attributes that related to the instance type. Defines argument as
name, type, and usage information.

    <argument
        name = "..."
        is_reference = "0 | 1"
      [ project = "..." ]
      [ uid = "..." ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | unsigned | size | byte | string | char | varargs" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ interface = "..." ]
      [ api = "..." ]
      [ impl = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ full_uid = "..." ]
      [ require_definition = "public | private" ]
      [ library = "..." ]
        >
        <string>, optional
        <array>, optional
    </argument>

The argument item can have these attributes:

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
    Argument name. The name attribute is required.


The 'variable' item
-------------------

Defines attributes that related to the instance type. Groups common
attributes for the component. Defines global variable.

    <variable
        name = "..."
        is_reference = "0 | 1"
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | unsigned | size | byte | string | char | varargs" ]
      [ project = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ interface = "..." ]
      [ api = "..." ]
      [ impl = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ library = "..." ]
      [ require_definition = "public | private" ]
      [ definition = "public | private | external"  ("private") ]
      [ declaration = "public | private | external"  ("public") ]
      [ visibility = "public | private"  ("public") ]
      [ c_namespace = "..." ]
      [ name_prefix = "..." ]
      [ uid = "..." ]
      [ full_uid = "..." ]
      [ feature = "..." ]
      [ class = "..." ]
        >
        <value>, 1 or more
        <string>, optional
        <array>, optional
    </variable>

The variable item can have these attributes:

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

c_namespace:
    Prefix that is used for C name resolution. The c_namespace attribute is
    optional.

name_prefix:
    Defines class name that a component belongs to. This attributes is used
    for inner components name resolution. The name_prefix attribute is optional.

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
    Object name. The name attribute is required.


The 'value' item
----------------

Defines attributes that related to the instance type. Initialization
variable value.

    <value
        is_reference = "0 | 1"
        value = "..."
      [ library = "..." ]
      [ type = "nothing | boolean | integer | unsigned | size | byte | string | char | varargs" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ interface = "..." ]
      [ api = "..." ]
      [ impl = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ project = "..." ]
      [ require_definition = "public | private" ]
      [ access = "readonly | writeonly | readwrite | disown" ]
        >
        <cast>, optional
        <string>, optional
        <array>, optional
    </value>

The value item can have these attributes:

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

value:
    Initialization value. The value attribute is required.


The 'cast' item
---------------

Defines attributes that related to the instance type. Cast parent instance
type to the type defined in this entity.

    <cast
        is_reference = "0 | 1"
      [ project = "..." ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | unsigned | size | byte | string | char | varargs" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ interface = "..." ]
      [ api = "..." ]
      [ impl = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ library = "..." ]
      [ require_definition = "public | private" ]
        >
        <string>, optional
        <array>, optional
    </cast>

The cast item can have these attributes:

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


The 'code' item
---------------

Contains language specific implementation body. For instance, method
implementation body for C language.

    <code
      [ lang = "c | java | csharp"  ("c") ]
      [ type = "stub | generated | handwritten"  ("generated") ]
        />

The code item can have these attributes:

lang:
    Defines target language this entity is applied to. The lang attribute is
    optional. Its default value is "c". It can take one of the following
    values:

Value: Meaning:
c: C language.
java: Java language.
csharp: C# language.

type:
    Defines implementation body originator. The type attribute is optional.
    Its default value is "generated". It can take one of the following
    values:

Value: Meaning:
stub: Implementation is just a stub, so method must be implemented by developer.
generated: Implementation is fully generated, so it must no be modified within source code.
handwritten: Implementation was written by developer, so it can be extracted and reused during generation phase. In this way comments and/or entity signature can be changed, but implementation will be untouched.


The 'inherit' item
------------------

Defines inherited interface.

    <inherit
        interface = "..."
        />

The inherit item has this single attribute:

interface:
    Inherited interface name. The interface attribute is required.

