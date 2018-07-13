Groups full features resolved for language: C.

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <c_features name source path>
       <c_feature [uid] [name] [default]>
          <c_require [feature]>
             <c_alternative [feature]/>
          </c_require>
       </c_feature>
    </c_features>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'c_features' item
---------------------

Groups full features resolved for language: C.

    <c_features
        name = "..."
        source = "project | library"
        path = "..."
        >
        <c_feature>
    </c_features>

The c_features item can have these attributes:

name:
    Features source name. The name attribute is required.

source:
    The source of grouped features. The source attribute is required. It can
    take one of the following values:

Value: Meaning:
project: Fetures are provided by inner project.
library: Fetures are provided by external library.

path:
    Path where generated files will come. The path attribute is required.


The 'c_feature' item
--------------------

Defines full qualified feature name.

    <c_feature
      [ uid = "..." ]
      [ name = "..." ]
      [ default = "on | off"  ("on") ]
        >
        <c_require>
    </c_feature>

The c_feature item can have these attributes:

uid:
    Unique component identifier represents name that uniquely identifies
    component within models hierarchy. The uid attribute is optional.

name:
    Full qualified feature name. The name attribute is optional.

default:
    Default feature state. The default attribute is optional. Its default
    value is "on". It can take one of the following values:

Value: Meaning:
on: Feature is enabled by default.
off: Feature is disabled by default.


The 'c_require' item
--------------------

Define required feature. Note, attribute 'feature' or inner entity
'alternative' must be defined. If attribute name is not defined, then at
least 2 'alternative' entities are expected.

    <c_require
      [ feature = "..." ]
        >
        <c_alternative>
    </c_require>

The c_require item has this single attribute:

feature:
    Required feature name. The feature attribute is optional.


The 'c_alternative' item
------------------------

Define alternative features that can be used, and in fact replace each
other.

    <c_alternative
      [ feature = "..." ]
        />

The c_alternative item has this single attribute:

feature:
    Required feature name. The feature attribute is optional.

