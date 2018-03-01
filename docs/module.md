Module groups high level logical components within one phisical
component.                                                     

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <module name [class] [uid] [scope] [c_prefix]>
       <require module [scope]/>
       <constant name value [uid] [scope] [c_prefix] [class]/>
       <enum [definition] [visibility] [c_prefix] [class] [uid] [scope] [name]>
          <enum_value name [class] [uid] [scope] [c_prefix] [value]/>
       </enum>
       <object name [access] [size] [enum] [callback] [definition] [visibility] [c_prefix]
            [class] [uid] [scope] [type]>
          <object_value value [uid]/>
          <array [access] [size]/>
       </object>
       <struct name [definition] [c_prefix] [class] [uid] [scope] [visibility]>
          <struct_property name [uid] [access] [type] [class] [enum] [callback] [size]>
             <argument name [uid] [access] [type] [class] [enum] [callback] [size]>
                <array .../>
             </argument>
             <return [size] [access] [type] [class] [enum] [callback]>
                <array .../>
             </return>
             <array .../>
          </struct_property>
       </struct>
       <callback name [class] [uid] [scope] [c_prefix]>
          <return .../>
          <argument .../>
       </callback>
       <method name [definition] [c_prefix] [class] [uid] [scope] [visibility]>
          <return .../>
          <argument .../>
          <c_implementation/>
       </method>
       <macros name [class] [uid] [scope] [c_prefix]>
          <c_implementation .../>
       </macros>
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
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
        >
        <require>
        <constant>
        <enum>
        <object>
        <struct>
        <callback>
        <method>
        <macros>
    </module>

The module item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

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
        value = "..."
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ class = "..." ]
        />

The constant item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

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
    Constant value. The value attribute is required.


The 'enum' item
---------------

Groups common attributes for the component. Defines enumeration type.

    <enum
      [ definition = "public | private | external"  ("private") ]
      [ visibility = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ name = "..." ]
        >
        <enum_value>
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

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Object name. The name attribute is optional.


The 'enum_value' item
---------------------

Groups common attributes for the component. Defines enumeration value.

    <enum_value
        name = "..."
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ value = "..." ]
        />

The enum_value item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Enumeration value name. The name attribute is required.

value:
    Enumeration value constant. The value attribute is optional.


The 'object' item
-----------------

Defines attributes that related to the instance type. Groups common
attributes for the component. Defines global object.               

    <object
        name = "..."
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ size = "1 | 2 | 4 | 8 | null_terminated | given | known | fixed | derived" ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ definition = "public | private | external"  ("private") ]
      [ visibility = "public | private"  ("public") ]
      [ c_prefix = "..." ]
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
        >
        <object_value>, 1 or more
        <array>
    </object>

The object item can have these attributes:

size:
    Define possible size types for instances and array of instances. The size
    attribute is optional. It can take one of the following values:          

Value: Meaning:
1: Size of the type is one byte.
2: Size of the type is two bytes.
4: Size of the type is three bytes.
8: Size of the type is four bytes.
null_terminated: String size or array size is defined by distance from the first to the termination symbol.
given: String size or array size is defined by the client.
known: Array size is known at compile time or during runtime, so it can be obtained by the client side and passed to the method as argument.
fixed: Array size is known at compile time so it can be checked.
derived: Array size can be statically derived during array initialization.

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

class:
    Defines instance class. Possible values are: * any - Defines instance of 
    any class. * string - String class. Have a special meaning in the C      
    context, it is represented a null-terminated array of characters. *      
    buffer - Special class "buffer" that is used as an output byte array. *  
    impl - Universal implementation class. If value differs from the listed  
    above then next algorithm applied: 1. If value in a format .(uid), then  
    it treated as a reference to the in-project class and will be substituted
    during context resolution step. 2. Any other value will be used as-is. So
    one third party type can be used. Short class name that is implmeneted in
    this module. This attributes is used for inner components name           
    resolution. The class attribute is optional.                             

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Object name. The name attribute is required.


The 'object_value' item
-----------------------

Initialization object value.

    <object_value
        value = "..."
      [ uid = "..." ]
        />

The object_value item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

value:
    Initialization value. The value attribute is required.


The 'array' item
----------------

Defines parent instance as an array.

    <array
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ size = "..." ]
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

size:
    For fixed size array it defines number of elements as integral constant.
    The size attribute is optional.                                         


The 'struct' item
-----------------

Groups common attributes for the component. Defines struct type.

    <struct
        name = "..."
      [ definition = "public | private | external"  ("private") ]
      [ c_prefix = "..." ]
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ visibility = "public | private"  ("public") ]
        >
        <struct_property>
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

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Structure name. The name attribute is required.


The 'struct_property' item
--------------------------

Defines attributes that related to the instance type. Defines struct
property.                                                           

    <struct_property
        name = "..."
      [ uid = "..." ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8 | null_terminated | given | known | fixed | derived" ]
        >
        <argument>
        <return>
        <array>
    </struct_property>

The struct_property item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

size:
    Define possible size types for instances and array of instances. The size
    attribute is optional. It can take one of the following values:          

Value: Meaning:
1: Size of the type is one byte.
2: Size of the type is two bytes.
4: Size of the type is three bytes.
8: Size of the type is four bytes.
null_terminated: String size or array size is defined by distance from the first to the termination symbol.
given: String size or array size is defined by the client.
known: Array size is known at compile time or during runtime, so it can be obtained by the client side and passed to the method as argument.
fixed: Array size is known at compile time so it can be checked.
derived: Array size can be statically derived during array initialization.

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

name:
    Property name. The name attribute is required.


The 'argument' item
-------------------

Defines attributes that related to the instance type. Defines argument as
name, type, and usage information.                                       

    <argument
        name = "..."
      [ uid = "..." ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
      [ size = "1 | 2 | 4 | 8 | null_terminated | given | known | fixed | derived" ]
        >
        <array>
    </argument>

The argument item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

size:
    Define possible size types for instances and array of instances. The size
    attribute is optional. It can take one of the following values:          

Value: Meaning:
1: Size of the type is one byte.
2: Size of the type is two bytes.
4: Size of the type is three bytes.
8: Size of the type is four bytes.
null_terminated: String size or array size is defined by distance from the first to the termination symbol.
given: String size or array size is defined by the client.
known: Array size is known at compile time or during runtime, so it can be obtained by the client side and passed to the method as argument.
fixed: Array size is known at compile time so it can be checked.
derived: Array size can be statically derived during array initialization.

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

name:
    Argument name. The name attribute is required.


The 'return' item
-----------------

Defines attributes that related to the instance type. Defines return type.

    <return
      [ size = "1 | 2 | 4 | 8 | null_terminated | given | known | fixed | derived" ]
      [ access = "readonly | writeonly | readwrite | disown" ]
      [ type = "nothing | boolean | integer | size | byte | data" ]
      [ class = "..." ]
      [ enum = "..." ]
      [ callback = "..." ]
        >
        <array>
    </return>

The return item can have these attributes:

size:
    Define possible size types for instances and array of instances. The size
    attribute is optional. It can take one of the following values:          

Value: Meaning:
1: Size of the type is one byte.
2: Size of the type is two bytes.
4: Size of the type is three bytes.
8: Size of the type is four bytes.
null_terminated: String size or array size is defined by distance from the first to the termination symbol.
given: String size or array size is defined by the client.
known: Array size is known at compile time or during runtime, so it can be obtained by the client side and passed to the method as argument.
fixed: Array size is known at compile time so it can be checked.
derived: Array size can be statically derived during array initialization.

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


The 'callback' item
-------------------

Groups common attributes for the component. Defines the callback signature.

    <callback
        name = "..."
      [ class = "..." ]
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

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

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
      [ class = "..." ]
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

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

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
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ c_prefix = "..." ]
        >
        <c_implementation>, optional
    </macros>

The macros item can have these attributes:

c_prefix:
    Prefix that is used for C name resolution. The c_prefix attribute is
    optional.                                                           

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. This attribute can be
    inherited. The scope attribute is optional. Its default value is
    "public". It can take one of the following values:              

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Macros name. The name attribute is required.

