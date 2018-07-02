Contains meta information about external library.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <library name [prefix]>
       <feature name [project] [library] [prefix]>
          <require [library] [project] [feature]>
             <alternative [library] [project] [feature]/>
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


The 'feature' item
------------------

Provide attributes that defines the source of feature. Define provided
feature.

    <feature
        name = "..."
      [ project = "..." ]
      [ library = "..." ]
      [ prefix = "..." ]
        >
        <require>
    </feature>

The feature item can have these attributes:

library:
    Name of the library that provides feature. By default this attribute is
    resolved to parent library name. The library attribute is optional.

project:
    Name of the project that provides feature. By default this attribute is
    resolved to parent project name. The project attribute is optional.

name:
    Feature name. The name attribute is required.

prefix:
    Feature prefix. This attribute is derived from parent's attribute
    'prefix'. The prefix attribute is optional.


The 'require' item
------------------

Provide attributes that defines the source of feature. Define required
feature. Note, attribute 'feature' or inner entity 'alternative' must be
defined. If attribute name is not defined, then at least 2 'alternative'
entities are expected.

    <require
      [ library = "..." ]
      [ project = "..." ]
      [ feature = "..." ]
        >
        <alternative>
    </require>

The require item can have these attributes:

library:
    Name of the library that provides feature. By default this attribute is
    resolved to parent library name. The library attribute is optional.

project:
    Name of the project that provides feature. By default this attribute is
    resolved to parent project name. The project attribute is optional.

feature:
    Required feature name. The feature attribute is optional.


The 'alternative' item
----------------------

Provide attributes that defines the source of feature. Define alternative
features that can be used, and in fact replace each other.

    <alternative
      [ library = "..." ]
      [ project = "..." ]
      [ feature = "..." ]
        />

The alternative item can have these attributes:

library:
    Name of the library that provides feature. By default this attribute is
    resolved to parent library name. The library attribute is optional.

project:
    Name of the project that provides feature. By default this attribute is
    resolved to parent project name. The project attribute is optional.

feature:
    Required feature name. The feature attribute is optional.

