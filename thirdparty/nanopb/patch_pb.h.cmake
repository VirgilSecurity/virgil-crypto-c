#   Copyright (C) 2015-2019 Virgil Security, Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.


file(READ pb.h content)


if(PB_ENABLE_MALLOC)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_ENABLE_MALLOC 1( \\*\\/)?"
            "#define PB_ENABLE_MALLOC 1" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_ENABLE_MALLOC 1( \\*\\/)?"
            "/* #define PB_ENABLE_MALLOC 1 */" content "${content}"
    )
endif()


if(PB_NO_PACKED_STRUCTS)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_NO_PACKED_STRUCTS 1( \\*\\/)?"
            "#define PB_NO_PACKED_STRUCTS 1" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_NO_PACKED_STRUCTS 1( \\*\\/)?"
            "/* #define PB_NO_PACKED_STRUCTS 1 */" content "${content}"
    )
endif()


if(PB_MAX_REQUIRED_FIELDS)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_MAX_REQUIRED_FIELDS 256( \\*\\/)?"
            "#define PB_MAX_REQUIRED_FIELDS 256" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_MAX_REQUIRED_FIELDS 256( \\*\\/)?"
            "/* #define PB_MAX_REQUIRED_FIELDS 256 */" content "${content}"
    )
endif()


if(PB_FIELD_16BIT)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_FIELD_16BIT 1( \\*\\/)?"
            "#define PB_FIELD_16BIT 1" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_FIELD_16BIT 1( \\*\\/)?"
            "/* #define PB_FIELD_16BIT 1 */" content "${content}"
    )
endif()


if(PB_FIELD_32BIT)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_FIELD_32BIT 1( \\*\\/)?"
            "#define PB_FIELD_32BIT 1" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_FIELD_32BIT 1( \\*\\/)?"
            "/* #define PB_FIELD_32BIT 1 */" content "${content}"
    )
endif()


if(PB_NO_ERRMSG)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_NO_ERRMSG 1( \\*\\/)?"
            "#define PB_NO_ERRMSG 1" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_NO_ERRMSG 1( \\*\\/)?"
            "/* #define PB_NO_ERRMSG 1 */" content "${content}"
    )
endif()


if(PB_BUFFER_ONLY)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_BUFFER_ONLY 1( \\*\\/)?"
            "#define PB_BUFFER_ONLY 1" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_BUFFER_ONLY 1( \\*\\/)?"
            "/* #define PB_BUFFER_ONLY 1 */" content "${content}"
    )
endif()


if(PB_OLD_CALLBACK_STYLE)
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_OLD_CALLBACK_STYLE 1( \\*\\/)?"
            "#define PB_OLD_CALLBACK_STYLE 1" content "${content}"
    )
else()
    string(REGEX REPLACE
            "(\\/\\* )?#define PB_OLD_CALLBACK_STYLE 1( \\*\\/)?"
            "/* #define PB_OLD_CALLBACK_STYLE 1 */" content "${content}"
    )
endif()


file (WRITE "pb.h" "${content}")
