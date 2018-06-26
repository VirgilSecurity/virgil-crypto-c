#   Copyright (c) 2015-2017 Virgil Security Inc.
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

include_guard()

#
#   Define boolean variable with feature name and value ON,
#   and add given feature to the features list.
#
if(NOT COMMAND _add_feature)
    macro(_add_feature list name)
        if(NOT DEFINED ${name})
            set(${name} ON)

            if(${name})
                list(APPEND ${list} ${name})
            endif()
        endif()
    endmacro()
endif()

set(MBEDTLS_FEATURES)

_add_feature(MBEDTLS_FEATURES MBEDTLS_SHA256_C)
_add_feature(MBEDTLS_FEATURES MBEDTLS_SHA512_C)
_add_feature(MBEDTLS_FEATURES MBEDTLS_CIPHER_C)
_add_feature(MBEDTLS_FEATURES MBEDTLS_AES_C)
_add_feature(MBEDTLS_FEATURES MBEDTLS_GCM_C)
_add_feature(MBEDTLS_FEATURES MBEDTLS_MD_C)
_add_feature(MBEDTLS_FEATURES MBEDTLS_CTR_DRBG_C)
_add_feature(MBEDTLS_FEATURES MBEDTLS_ENTROPY_C)

list(REMOVE_DUPLICATES MBEDTLS_FEATURES)
