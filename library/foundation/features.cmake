#   Copyright (C) 2015-2018 Virgil Security Inc.
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
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


include_guard()

option(VSCF_CIPHER "Enable interface 'cipher'." ON)
option(VSCF_AUTH_ENCRYPT "Enable interface 'auth encrypt'." ON)
option(VSCF_AUTH_DECRYPT "Enable interface 'auth decrypt'." ON)
option(VSCF_CIPHER_AUTH "Enable interface 'cipher auth'." ON)
option(VSCF_CIPHER_AUTH_INFO "Enable interface 'cipher auth info'." ON)
option(VSCF_CIPHER_INFO "Enable interface 'cipher info'." ON)
option(VSCF_DECRYPT "Enable interface 'decrypt'." ON)
option(VSCF_ENCRYPT "Enable interface 'encrypt'." ON)
option(VSCF_EX_KDF "Enable interface 'ex_kdf'." ON)
option(VSCF_HASH "Enable interface 'hash'." ON)
option(VSCF_HASH_INFO "Enable interface 'hash info'." ON)
option(VSCF_HASH_STREAM "Enable interface 'hash stream'." ON)
option(VSCF_HMAC "Enable interface 'hmac'." ON)
option(VSCF_HMAC_INFO "Enable interface 'hmac info'." ON)
option(VSCF_HMAC_STREAM "Enable interface 'hmac stream'." ON)
option(VSCF_KDF "Enable interface 'kdf'." ON)
option(VSCF_HMAC224 "Enable implementation 'hmac224'." ON)
option(VSCF_HMAC256 "Enable implementation 'hmac256'." ON)
option(VSCF_HMAC384 "Enable implementation 'hmac384'." ON)
option(VSCF_HMAC512 "Enable implementation 'hmac512'." ON)
option(VSCF_SHA224 "Enable implementation 'sha224'." ON)
option(VSCF_SHA256 "Enable implementation 'sha256'." ON)
option(VSCF_SHA384 "Enable implementation 'sha384'." ON)
option(VSCF_SHA512 "Enable implementation 'sha512'." ON)
option(VSCF_AES256_GCM "Enable implementation 'aes256 gcm'." ON)
option(VSCF_HKDF "Enable implementation 'hkdf'." ON)
option(VSCF_KDF1 "Enable implementation 'kdf1'." ON)
option(VSCF_KDF2 "Enable implementation 'kdf2'." ON)

if(VSCF_CIPHER AND NOT VSCF_ENCRYPT)
    message(FATAL_ERROR "Feature VSCF_CIPHER depends on the feature: VSCF_ENCRYPT - which is disabled.")
endif()

if(VSCF_CIPHER AND NOT VSCF_DECRYPT)
    message(FATAL_ERROR "Feature VSCF_CIPHER depends on the feature: VSCF_DECRYPT - which is disabled.")
endif()

if(VSCF_CIPHER AND NOT VSCF_CIPHER_INFO)
    message(FATAL_ERROR "Feature VSCF_CIPHER depends on the feature: VSCF_CIPHER_INFO - which is disabled.")
endif()

if(VSCF_CIPHER_AUTH AND NOT VSCF_CIPHER_AUTH_INFO)
    message(FATAL_ERROR "Feature VSCF_CIPHER_AUTH depends on the feature: VSCF_CIPHER_AUTH_INFO - which is disabled.")
endif()

if(VSCF_CIPHER_AUTH AND NOT VSCF_AUTH_ENCRYPT)
    message(FATAL_ERROR "Feature VSCF_CIPHER_AUTH depends on the feature: VSCF_AUTH_ENCRYPT - which is disabled.")
endif()

if(VSCF_CIPHER_AUTH AND NOT VSCF_AUTH_DECRYPT)
    message(FATAL_ERROR "Feature VSCF_CIPHER_AUTH depends on the feature: VSCF_AUTH_DECRYPT - which is disabled.")
endif()

if(VSCF_HASH AND NOT VSCF_HASH_INFO)
    message(FATAL_ERROR "Feature VSCF_HASH depends on the feature: VSCF_HASH_INFO - which is disabled.")
endif()

if(VSCF_HASH_STREAM AND NOT VSCF_HASH_INFO)
    message(FATAL_ERROR "Feature VSCF_HASH_STREAM depends on the feature: VSCF_HASH_INFO - which is disabled.")
endif()

if(VSCF_HMAC AND NOT VSCF_HMAC_INFO)
    message(FATAL_ERROR "Feature VSCF_HMAC depends on the feature: VSCF_HMAC_INFO - which is disabled.")
endif()

if(VSCF_HMAC_STREAM AND NOT VSCF_HMAC_INFO)
    message(FATAL_ERROR "Feature VSCF_HMAC_STREAM depends on the feature: VSCF_HMAC_INFO - which is disabled.")
endif()

if(VSCF_HMAC224 AND NOT MBEDTLS_MD_C)
    message(FATAL_ERROR "Feature VSCF_HMAC224 depends on the feature: MBEDTLS_MD_C - which is disabled.")
endif()

if(VSCF_HMAC224 AND NOT MBEDTLS_SHA256_C)
    message(FATAL_ERROR "Feature VSCF_HMAC224 depends on the feature: MBEDTLS_SHA256_C - which is disabled.")
endif()

if(VSCF_HMAC256 AND NOT MBEDTLS_MD_C)
    message(FATAL_ERROR "Feature VSCF_HMAC256 depends on the feature: MBEDTLS_MD_C - which is disabled.")
endif()

if(VSCF_HMAC256 AND NOT MBEDTLS_SHA256_C)
    message(FATAL_ERROR "Feature VSCF_HMAC256 depends on the feature: MBEDTLS_SHA256_C - which is disabled.")
endif()

if(VSCF_HMAC256 AND NOT MBEDTLS_SHA256_C)
    message(FATAL_ERROR "Feature VSCF_HMAC256 depends on the feature: MBEDTLS_SHA256_C - which is disabled.")
endif()

if(VSCF_HMAC384 AND NOT MBEDTLS_MD_C)
    message(FATAL_ERROR "Feature VSCF_HMAC384 depends on the feature: MBEDTLS_MD_C - which is disabled.")
endif()

if(VSCF_HMAC384 AND NOT MBEDTLS_SHA512_C)
    message(FATAL_ERROR "Feature VSCF_HMAC384 depends on the feature: MBEDTLS_SHA512_C - which is disabled.")
endif()

if(VSCF_HMAC512 AND NOT MBEDTLS_MD_C)
    message(FATAL_ERROR "Feature VSCF_HMAC512 depends on the feature: MBEDTLS_MD_C - which is disabled.")
endif()

if(VSCF_HMAC512 AND NOT MBEDTLS_SHA512_C)
    message(FATAL_ERROR "Feature VSCF_HMAC512 depends on the feature: MBEDTLS_SHA512_C - which is disabled.")
endif()

if(VSCF_SHA224 AND NOT MBEDTLS_SHA256_C)
    message(FATAL_ERROR "Feature VSCF_SHA224 depends on the feature: MBEDTLS_SHA256_C - which is disabled.")
endif()

if(VSCF_SHA256 AND NOT MBEDTLS_SHA256_C)
    message(FATAL_ERROR "Feature VSCF_SHA256 depends on the feature: MBEDTLS_SHA256_C - which is disabled.")
endif()

if(VSCF_SHA384 AND NOT MBEDTLS_SHA512_C)
    message(FATAL_ERROR "Feature VSCF_SHA384 depends on the feature: MBEDTLS_SHA512_C - which is disabled.")
endif()

if(VSCF_SHA512 AND NOT MBEDTLS_SHA512_C)
    message(FATAL_ERROR "Feature VSCF_SHA512 depends on the feature: MBEDTLS_SHA512_C - which is disabled.")
endif()

if(VSCF_AES256_GCM AND NOT MBEDTLS_CIPHER_C)
    message(FATAL_ERROR "Feature VSCF_AES256_GCM depends on the feature: MBEDTLS_CIPHER_C - which is disabled.")
endif()

if(VSCF_HKDF AND NOT VSCF_HMAC_STREAM)
    message(FATAL_ERROR "Feature VSCF_HKDF depends on the feature: VSCF_HMAC_STREAM - which is disabled.")
endif()

if(VSCF_KDF1 AND NOT VSCF_HASH_STREAM)
    message(FATAL_ERROR "Feature VSCF_KDF1 depends on the feature: VSCF_HASH_STREAM - which is disabled.")
endif()

if(VSCF_KDF2 AND NOT VSCF_HASH_STREAM)
    message(FATAL_ERROR "Feature VSCF_KDF2 depends on the feature: VSCF_HASH_STREAM - which is disabled.")
endif()
