Contains meta information about external library.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <library name path [prefix]>
       <feature name [library] [project] [prefix] [default]>
          <require [scope] [project] [library] [module] [header] [feature] [interface] [class]
               [impl] [enum]>
             <alternative [scope] [project] [library] [module] [header] [feature] [interface] [class]
                  [impl] [enum]/>
          </require>
       </feature>
    </library>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'library' item
------------------

Contains meta information about external library.

    <library
        name = "..."
        path = "..."
      [ prefix = "..." ]
        >
        <feature>
    </library>

The library item can have these attributes:

name:
    Library in-project name. The name attribute is required.

prefix:
    Prefix for names within library. If not defined, then it equals to
    library name. Can be explicitly empty. The prefix attribute is optional.

path:
    Path to the library root directory. The path attribute is required.


The 'feature' item
------------------

Define provided feature.

    <feature
        name = "..."
      [ library = "..." ]
      [ project = "..." ]
      [ prefix = "..." ]
      [ default = "on | off"  ("on") ]
        >
        <require>
    </feature>

The feature item can have these attributes:

project:
    Defines project name that component refers to. The project attribute is
    optional.

library:
    Defines library name that component refers to. The library attribute is
    optional.

name:
    Feature name. The name attribute is required.

prefix:
    Feature prefix. This attribute is derived from parent's attribute
    'prefix'. The prefix attribute is optional.

default:
    Default feature state. The default attribute is optional. Its default
    value is "on". It can take one of the following values:

Value: Meaning:
on: Feature is enabled by default.
off: Feature is disabled by default.


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

