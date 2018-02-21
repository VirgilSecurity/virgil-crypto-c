Module groups high level logical components within one phisical
component.                                                     

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <module name [uid] [scope] [class]>
       <require module [scope]/>
       <constant value name [scope] [uid] [class]/>
       <enum [visibility] [class] [uid] [scope] [name]>
          <enum_value name [value]/>
       </enum>
       <object type name [io] [visibility] [class] [uid] [scope] [is_array]>
          <c_type base [is_callback] [kind] [array] [is_const_type] [is_const_pointer] [is_const_array]
               [is_const_reference]/>
       </object>
       <struct name [class] [uid] [scope] [visibility]>
          <struct_property type name [io] [uid] [is_array] [is_callback]>
             <argument name type [is_array] [io] [uid]>
                <c_type .../>
             </argument>
             <return type [is_array] [io]>
                <c_type .../>
             </return>
             <c_type .../>
          </struct_property>
       </struct>
       <callback name [class] [uid] [scope] [visibility]>
          <return .../>
          <argument .../>
          <c_implementation/>
       </callback>
       <method name [class] [uid] [scope] [visibility]>
          <return .../>
          <argument .../>
          <c_implementation .../>
       </method>
       <macros name [uid] [scope] [class]>
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
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ class = "..." ]
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

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

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
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

module:
    Module name that current module depends on. The module attribute is
    required.                                                          


The 'constant' item
-------------------

Groups common attributes for the component. Defines intergral constant.

    <constant
        value = "..."
        name = "..."
      [ scope = "public | private"  ("public") ]
      [ uid = "..." ]
      [ class = "..." ]
        />

The constant item can have these attributes:

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

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
      [ visibility = "public | private"  ("public") ]
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ name = "..." ]
        >
        <enum_value>
    </enum>

The enum item can have these attributes:

visibility:
    Defines symbol binary visibility. The visibility attribute is optional.
    Its default value is "public". It can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Object name. The name attribute is optional.


The 'enum_value' item
---------------------

Defines enumeration value.

    <enum_value
        name = "..."
      [ value = "..." ]
        />

The enum_value item can have these attributes:

name:
    Enumeration value name. The name attribute is required.

value:
    Enumeration value constant. The value attribute is optional.


The 'object' item
-----------------

Defines attributes that related to the instance type. Groups common
attributes for the component. Defines global object.               

    <object
        type = "nothing | any | boolean | integer | size | byte | string | data | buffer | impl"
        name = "..."
      [ io = "in | out | inout | release" ]
      [ visibility = "public | private"  ("public") ]
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ is_array = "0 | 1"  ("0") ]
        >
        <c_type>
    </object>

The object item can have these attributes:

type:
    Defines type of the instance, argument, struct property, object. The type
    attribute is required. It can take one of the following values:          

Value: Meaning:
nothing: The same as a C void type.
any: Value of any can be passed.
boolean: True / False type.
integer: Signed integral type.
size: Unsigned integral type for size difinition.
byte: Unsigned 8-bit integral type.
string: Self contained string. In the C context it is represented as a null-terminated string.
data: Shortcut for the byte array.
buffer: Special type that refers to the class "buffer".
impl: Special type that refers to the universal implementation type.

is_array:
    Defines whether given type is an array. The is_array attribute is   
    optional. Its default value is "0". It can take one of the following
    values:                                                             

Value: Meaning:
0: Regular type.
1: Array type.

io:
    Defines type purposes. The io attribute is optional. It can take one of
    the following values:                                                  

Value: Meaning:
in: Value of the given type is readonly.
out: Value of the given type is always re-written.
inout: Value of the given type can be read and then be re-written.
release: Ownership of the given value is transferred to someone else, so client can not use this value anymore.

visibility:
    Defines symbol binary visibility. The visibility attribute is optional.
    Its default value is "public". It can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Object name. The name attribute is required.


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


The 'struct' item
-----------------

Groups common attributes for the component. Defines struct type.

    <struct
        name = "..."
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ visibility = "public | private"  ("public") ]
        >
        <struct_property>
    </struct>

The struct item can have these attributes:

visibility:
    Defines symbol binary visibility. The visibility attribute is optional.
    Its default value is "public". It can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

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
        type = "nothing | any | boolean | integer | size | byte | string | data | buffer | impl"
        name = "..."
      [ io = "in | out | inout | release" ]
      [ uid = "..." ]
      [ is_array = "0 | 1"  ("0") ]
      [ is_callback = "0 | 1" ]
        >
        <argument>
        <return>
        <c_type>
    </struct_property>

The struct_property item can have these attributes:

type:
    Defines type of the instance, argument, struct property, object. The type
    attribute is required. It can take one of the following values:          

Value: Meaning:
nothing: The same as a C void type.
any: Value of any can be passed.
boolean: True / False type.
integer: Signed integral type.
size: Unsigned integral type for size difinition.
byte: Unsigned 8-bit integral type.
string: Self contained string. In the C context it is represented as a null-terminated string.
data: Shortcut for the byte array.
buffer: Special type that refers to the class "buffer".
impl: Special type that refers to the universal implementation type.

is_array:
    Defines whether given type is an array. The is_array attribute is   
    optional. Its default value is "0". It can take one of the following
    values:                                                             

Value: Meaning:
0: Regular type.
1: Array type.

io:
    Defines type purposes. The io attribute is optional. It can take one of
    the following values:                                                  

Value: Meaning:
in: Value of the given type is readonly.
out: Value of the given type is always re-written.
inout: Value of the given type can be read and then be re-written.
release: Ownership of the given value is transferred to someone else, so client can not use this value anymore.

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

name:
    Property name. The name attribute is required.

is_callback:
    Defines if property defines a callback. The is_callback attribute is
    optional. It can take one of the following values:                  

Value: Meaning:
0: Field.
1: Callback.


The 'argument' item
-------------------

Defines attributes that related to the instance type. Defines argument as
name, type, and usage information.                                       

    <argument
        name = "..."
        type = "nothing | any | boolean | integer | size | byte | string | data | buffer | impl"
      [ is_array = "0 | 1"  ("0") ]
      [ io = "in | out | inout | release" ]
      [ uid = "..." ]
        >
        <c_type>
    </argument>

The argument item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

type:
    Defines type of the instance, argument, struct property, object. The type
    attribute is required. It can take one of the following values:          

Value: Meaning:
nothing: The same as a C void type.
any: Value of any can be passed.
boolean: True / False type.
integer: Signed integral type.
size: Unsigned integral type for size difinition.
byte: Unsigned 8-bit integral type.
string: Self contained string. In the C context it is represented as a null-terminated string.
data: Shortcut for the byte array.
buffer: Special type that refers to the class "buffer".
impl: Special type that refers to the universal implementation type.

is_array:
    Defines whether given type is an array. The is_array attribute is   
    optional. Its default value is "0". It can take one of the following
    values:                                                             

Value: Meaning:
0: Regular type.
1: Array type.

io:
    Defines type purposes. The io attribute is optional. It can take one of
    the following values:                                                  

Value: Meaning:
in: Value of the given type is readonly.
out: Value of the given type is always re-written.
inout: Value of the given type can be read and then be re-written.
release: Ownership of the given value is transferred to someone else, so client can not use this value anymore.

name:
    Argument name. The name attribute is required.


The 'return' item
-----------------

Defines attributes that related to the instance type. Defines return type.

    <return
        type = "nothing | any | boolean | integer | size | byte | string | data | buffer | impl"
      [ is_array = "0 | 1"  ("0") ]
      [ io = "in | out | inout | release" ]
        >
        <c_type>
    </return>

The return item can have these attributes:

type:
    Defines type of the instance, argument, struct property, object. The type
    attribute is required. It can take one of the following values:          

Value: Meaning:
nothing: The same as a C void type.
any: Value of any can be passed.
boolean: True / False type.
integer: Signed integral type.
size: Unsigned integral type for size difinition.
byte: Unsigned 8-bit integral type.
string: Self contained string. In the C context it is represented as a null-terminated string.
data: Shortcut for the byte array.
buffer: Special type that refers to the class "buffer".
impl: Special type that refers to the universal implementation type.

is_array:
    Defines whether given type is an array. The is_array attribute is   
    optional. Its default value is "0". It can take one of the following
    values:                                                             

Value: Meaning:
0: Regular type.
1: Array type.

io:
    Defines type purposes. The io attribute is optional. It can take one of
    the following values:                                                  

Value: Meaning:
in: Value of the given type is readonly.
out: Value of the given type is always re-written.
inout: Value of the given type can be read and then be re-written.
release: Ownership of the given value is transferred to someone else, so client can not use this value anymore.


The 'callback' item
-------------------

Groups common attributes for the component. Defines the method signature
and optionally implementaiton.                                          

    <callback
        name = "..."
      [ class = "..." ]
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ visibility = "public | private"  ("public") ]
        >
        <return>, optional
        <argument>
        <c_implementation>, optional
    </callback>

The callback item can have these attributes:

visibility:
    Defines symbol binary visibility. The visibility attribute is optional.
    Its default value is "public". It can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Method name. The name attribute is required.


The 'c_implementation' item
---------------------------

Defines method or macros implementation.

    <c_implementation>



The 'method' item
-----------------

Groups common attributes for the component. Defines the method signature
and optionally implementaiton.                                          

    <method
        name = "..."
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

visibility:
    Defines symbol binary visibility. The visibility attribute is optional.
    Its default value is "public". It can take one of the following values:

Value: Meaning:
public: Symbols of the types and methods are visible in a binary file.
private: Symbols of the types and methods are hidden in a binary file.

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Method name. The name attribute is required.


The 'macros' item
-----------------

Groups common attributes for the component. Defines the macros name and
optionally implementaiton.                                             

    <macros
        name = "..."
      [ uid = "..." ]
      [ scope = "public | private"  ("public") ]
      [ class = "..." ]
        >
        <c_implementation>, optional
    </macros>

The macros item can have these attributes:

class:
    Short class name that is implmeneted in this module. This attributes is
    used for inner components name resolution. The class attribute is      
    optional.                                                              

uid:
    Unique component identifier represents name that uniquely identifies
    component within modules hierarchy. The uid attribute is optional.  

scope:
    Defines component visibility within scope. The scope attribute is        
    optional. Its default value is "public". It can take one of the following
    values:                                                                  

Value: Meaning:
public: Component is visible for outside world.
private: Component is visible only within library or a specific source file.

name:
    Macros name. The name attribute is required.

