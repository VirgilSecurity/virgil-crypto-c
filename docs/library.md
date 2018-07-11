Contains meta information about external library.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <library name path [prefix]>
       <feature name [prefix]>
          <source [name] [type]/>
          <require [feature]>
             <source .../>
             <alternative [feature]>
                <source .../>
             </alternative>
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
      [ prefix = "..." ]
        >
        <source>, required
        <require>
    </feature>

The feature item can have these attributes:

name:
    Feature name. The name attribute is required.

prefix:
    Feature prefix. This attribute is derived from parent's attribute
    'prefix'. The prefix attribute is optional.


The 'source' item
-----------------

Provide attributes that defines the source of featur(e). This entity is
inherited.

    <source
      [ name = "..." ]
      [ type = "project | library" ]
        />

The source item can have these attributes:

name:
    Source name The name attribute is optional.

type:
    The source type of the feature(s). The type attribute is optional. It can
    take one of the following values:

Value: Meaning:
project: Feture(s) are provided by inner project.
library: Feture(s) are provided by external library.


The 'require' item
------------------

Define required feature. Note, attribute 'feature' or inner entity
'alternative' must be defined. If attribute name is not defined, then at
least 2 'alternative' entities are expected.

    <require
      [ feature = "..." ]
        >
        <source>, required
        <alternative>
    </require>

The require item has this single attribute:

feature:
    Required feature name. The feature attribute is optional.


The 'alternative' item
----------------------

Define alternative features that can be used, and in fact replace each
other.

    <alternative
      [ feature = "..." ]
        >
        <source>, required
    </alternative>

The alternative item has this single attribute:

feature:
    Required feature name. The feature attribute is optional.

