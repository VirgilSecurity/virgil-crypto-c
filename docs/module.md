Module groups high level logical components within one phisical
component.                                                     

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <module name [of_class] [uid] [scope] [c_prefix]>
       <require module [scope]/>
       <constant name [of_class] [uid] [scope] [c_prefix] [value]/>
       <enum [definition] [visibility] [c_prefix] [of_class] [uid] [scope] [name]>
          <constant .../>
       </enum>
       <variable name [type] [access] [enum] [callback] [size] [definition] [visibility] [c_prefix]
            [of_class] [uid] [scope] [class]>
          <value value [access] [class] [enum] [callback] [size] [type]>
             <string [length]/>
             <array [access] [length] [length_constant]/>
          </value>
          <string .../>
          <array .../>
       </variable>
       <struct name [definition] [c_prefix] [of_class] [uid] [scope] [visibility]>
          <property name [access] [type] [class] [enum] [callback] [size] [uid] [bits]>
             <argument name [uid] [type] [class] [enum] [callback] [size] [access]>
                <string .../>
                <array .../>
             </argument>
             <return [access] [type] [class] [enum] [callback] [size]>
                <string .../>
                <array .../>
             </return>
             <string .../>
             <array .../>
          </property>
       </struct>
       <callback name [of_class] [uid] [scope] [c_prefix]>
          <return .../>
          <argument .../>
       </callback>
       <method name [definition] [c_prefix] [of_class] [uid] [scope] [visibility]>
          <return .../>
          <argument .../>
          <c_implementation/>
       </method>
       <macros name [of_class] [uid] [scope] [c_prefix] [is_method]>
          <c_implementation .../>
       </macros>
       <macroses [scope]>
          <macros .../>
          <c_implementation .../>
       </macroses>
    </module>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'module' item
-----------------

Groups common attributes for the component. Module groups high level      
logical components within one phisical component. Phisical component is a 
source file, plus header file for C/C++. Logical component is             
representation of a constant, type, enumeration, method, etc. Module      
represents C components in a language agnostic way. This makes possible to
generate wrappers for high level languakes like C#, Java, Python, etc.    

    <module
        name = "..."
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
        >
        <require>
        <constant>
        <enum>
        <variable>
        <struct>
        <callback>
        <method>
        <macros>
        <macroses>
    </module>

The module item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Short module name. The name attribute is required.


The 'require' item
------------------

Defines module that current module depends on.

    <require
        module = "..."
      [ scope = "public | private"  ("public") ]
        />

The require item can have these attributes:

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

module:
    Module name that current module depends on. The module attribute is
    required.                                                          


The 'constant' item
-------------------

Groups common attributes for the component. Defines integral constant.

    <constant
        name = "..."
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ value = "..." ]
        />

The constant item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Constant value. Optional for enumerated constant. The value attribute is
    optional.                                                               


The 'enum' item
---------------

Groups common attributes for the component. Defines enumeration type.

    <enum
      [ definition = "public | private | external"  ("private") ]
      [ visibility = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ name = "..." ]
        >
        <constant>
    </enum>

The enum item can have these attributes:

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

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Object name. The name attribute is optional.


The 'variable' item
-------------------

Defines attributes that related to the instance type. Groups common
attributes for the component. Defines global variable.             

    <variable
        name = "..."
      [ type = "nothing | boolean | integer | size | byte | data" ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ definition = "public | private | external"  ("private") ]
      [ visibility = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ class = "..." ]
        >
        <value>, 1 or more
        <string>, optional
        <array>, optional
    </variable>

The variable item can have these attributes:

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

class:
    Defines instance class. Possible values are: * any - Defines instance of 
    any class. * string - String class. Have a special meaning in the C      
    context, it is represented a null-terminated array of characters. *      
    buffer - Special class "buffer" that is used as an output byte array. *  
    impl - Universal implementation class. If value differs from the listed  
    above then next algorithm applied: 1. If value in a format .(uid), then  
    it treated as a reference to the in-project class and will be substituted
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

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Object name. The name attribute is required.


The 'value' item
----------------

Defines attributes that related to the instance type. Initialization
variable value.                                                     

    <value
        value = "..."
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
        >
        <string>, optional
        <array>, optional
    </value>

The value item can have these attributes:

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

class:
    Defines instance class. Possible values are: * any - Defines instance of 
    any class. * string - String class. Have a special meaning in the C      
    context, it is represented a null-terminated array of characters. *      
    buffer - Special class "buffer" that is used as an output byte array. *  
    impl - Universal implementation class. If value differs from the listed  
    above then next algorithm applied: 1. If value in a format .(uid), then  
    it treated as a reference to the in-project class and will be substituted
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

value:
    Initialization value. The value attribute is required.


The 'string' item
-----------------

Defines restrictions to the special class 'string'.

    <string
      [ length = "null_terminated | given"  ("null_terminated") ]
        />

The string item has this single attribute:

length:
    Defines string length. The length attribute is optional. Its default
    value is "null_terminated". It can take one of the following values:

Value: Meaning:
null_terminated: String length is defined by distance from the first character up to the termination symbol (aka '\0').
given: String length is given from the client.


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


The 'struct' item
-----------------

Groups common attributes for the component. Defines struct type.

    <struct
        name = "..."
      [ definition = "public | private | external"  ("private") ]
      [ c_prefix = "..." ]
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ visibility = "public | private"  ("public") ]
        >
        <property>
    </struct>

The struct item can have these attributes:

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

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Structure name. The name attribute is required.


The 'property' item
-------------------

Defines attributes that related to the instance type. Defines struct
property.                                                           

    <property
        name = "..."
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ uid = "..." ]
      [ bits = "..." ]
        >
        <argument>
        <return>
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

class:
    Defines instance class. Possible values are: * any - Defines instance of 
    any class. * string - String class. Have a special meaning in the C      
    context, it is represented a null-terminated array of characters. *      
    buffer - Special class "buffer" that is used as an output byte array. *  
    impl - Universal implementation class. If value differs from the listed  
    above then next algorithm applied: 1. If value in a format .(uid), then  
    it treated as a reference to the in-project class and will be substituted
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

name:
    Property name. The name attribute is required.

bits:
    Define number of bits occupied by the property with integral type. The
    bits attribute is optional.                                           


The 'argument' item
-------------------

Defines attributes that related to the instance type. Defines argument as
name, type, and usage information.                                       

    <argument
        name = "..."
      [ uid = "..." ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
      [ access = "readonly | writeonly | readwrite | disown" ]
        >
        <string>, optional
        <array>, optional
    </argument>

The argument item can have these attributes:

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

class:
    Defines instance class. Possible values are: * any - Defines instance of 
    any class. * string - String class. Have a special meaning in the C      
    context, it is represented a null-terminated array of characters. *      
    buffer - Special class "buffer" that is used as an output byte array. *  
    impl - Universal implementation class. If value differs from the listed  
    above then next algorithm applied: 1. If value in a format .(uid), then  
    it treated as a reference to the in-project class and will be substituted
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

name:
    Argument name. The name attribute is required.


The 'return' item
-----------------

Defines attributes that related to the instance type. Defines return type.

    <return
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8" ]
        >
        <string>, optional
        <array>, optional
    </return>

The return item can have these attributes:

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

class:
    Defines instance class. Possible values are: * any - Defines instance of 
    any class. * string - String class. Have a special meaning in the C      
    context, it is represented a null-terminated array of characters. *      
    buffer - Special class "buffer" that is used as an output byte array. *  
    impl - Universal implementation class. If value differs from the listed  
    above then next algorithm applied: 1. If value in a format .(uid), then  
    it treated as a reference to the in-project class and will be substituted
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


The 'callback' item
-------------------

Groups common attributes for the component. Defines the callback signature.

    <callback
        name = "..."
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
        >
        <return>, optional
        <argument>
    </callback>

The callback item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Method name. The name attribute is required.


The 'method' item
-----------------

Groups common attributes for the component. Defines the method signature
and optionally implementation.                                          

    <method
        name = "..."
      [ definition = "public | private | external"  ("private") ]
      [ c_prefix = "..." ]
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ visibility = "public | private"  ("public") ]
        >
        <return>, optional
        <argument>
        <c_implementation>, optional
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

visibility:
    Defines symbol binary visibility. This attribute must not be inherited.
    The visibility attribute is optional. Its default value is "public". It
    can take one of the following values:                                  

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Method name. The name attribute is required.


The 'c_implementation' item
---------------------------

Defines method or macros implementation.

    <c_implementation>



The 'macros' item
-----------------

Groups common attributes for the component. Defines the macros name and
optionally implementation.                                             

    <macros
        name = "..."
      [ of_class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ is_method = "0 | 1"  ("0") ]
        >
        <c_implementation>, optional
    </macros>

The macros item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

of_class:
    Defines class name that a component belongs to. This attributes is used  
    for inner components name resolution. The of_class attribute is optional.

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
    Macros name. The name attribute is required.

is_method:
    Defines whether macros if it can accept argument(s). The is_method     
    attribute is optional. Its default value is "0". It can take one of the
    following values:                                                      

Value: Meaning:
0: Macros is a constant.
1: Macros is a method.


The 'macroses' item
-------------------

Group a set of macroses with common implemenatation.

    <macroses
      [ scope = "public | private"  ("public") ]
        >
        <macros>, 1 or more
        <c_implementation>, required
    </macroses>

The macroses item has this single attribute:

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

