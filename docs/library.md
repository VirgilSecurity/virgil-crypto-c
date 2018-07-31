Contains meta information about external library.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <library name path [prefix]>
       <feature name [library] [project] [prefix] [default]>
          <require [scope] [project] [library] [module] [header] [feature] [class]>
             <alternative [scope] [project] [library] [module] [header] [feature] [class]/>
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

Defines whom component belongs to. Define provided feature.

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
    Defines project name that component belongs to. The project attribute is
    optional.

library:
    Defines libary name that component belongs to. The library attribute is
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

Defines whom component belongs to. Base attributes for require. Defines
dependency to: module, header, feature.

    <require
      [ scope = "public | private | internal"  ("public") ]
      [ project = "..." ]
      [ library = "..." ]
      [ module = "..." ]
      [ header = "..." ]
      [ feature = "..." ]
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

class:
    Required class name. The class attribute is optional.

