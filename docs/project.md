Define project as set of interfaces, implementators and modules.s

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <project name brief prefix namespace path inc_path inc_private_path src_path work_path>
       <interface name/>
       <implementor name/>
       <module name/>
       <feature name [library] [project] [prefix] [default]>
          <require [scope] [project] [library] [module] [header] [feature] [class]>
             <alternative [scope] [project] [library] [module] [header] [feature] [class]/>
          </require>
       </feature>
    </project>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'project' item
------------------

Define project as set of interfaces, implementators and modules.

    <project
        name = "..."
        brief = "..."
        prefix = "..."
        namespace = "..."
        path = "..."
        inc_path = "..."
        inc_private_path = "..."
        src_path = "..."
        work_path = "..."
        >
        <interface>
        <implementor>
        <module>
        <feature>
    </project>

The project item can have these attributes:

name:
    Project name. The name attribute is required.

brief:
    Project brief description. The brief attribute is required.

prefix:
    Prefix for C names within project. The prefix attribute is required.

namespace:
    Project namespace. This attribute is used to for wrappers that support
    namesapces. The namespace attribute is required.

path:
    Path to the project root directory. The path attribute is required.

inc_path:
    Path to the directory with public headers. The inc_path attribute is
    required.

inc_private_path:
    Path to the directory with private headers. The inc_private_path
    attribute is required.

src_path:
    Path to the directory with source files. The src_path attribute is
    required.

work_path:
    Path to the directory, that is used to hold temporary files. The
    work_path attribute is required.


The 'interface' item
--------------------

Define supported interface.

    <interface
        name = "..."
        />

The interface item has this single attribute:

name:
    Interface name. The name attribute is required.


The 'implementor' item
----------------------

Define supported implementor.

    <implementor
        name = "..."
        />

The implementor item has this single attribute:

name:
    Implementor name. The name attribute is required.


The 'module' item
-----------------

Define supported module.

    <module
        name = "..."
        />

The module item has this single attribute:

name:
    Module name. The name attribute is required.


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

