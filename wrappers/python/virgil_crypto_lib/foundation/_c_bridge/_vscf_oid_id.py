# Copyright (C) 2015-2019 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from ctypes import *


class VscfOidId(object):

    NONE = 0
    RSA = 1
    ED25519 = 2
    CURVE25519 = 3
    SHA224 = 4
    SHA256 = 5
    SHA384 = 6
    SHA512 = 7
    KDF1 = 8
    KDF2 = 9
    AES256_GCM = 10
    AES256_CBC = 11
    PKCS5_PBKDF2 = 12
    PKCS5_PBES2 = 13
    CMS_DATA = 14
    CMS_ENVELOPED_DATA = 15
    HKDF_WITH_SHA256 = 16
    HKDF_WITH_SHA384 = 17
    HKDF_WITH_SHA512 = 18
    HMAC_WITH_SHA224 = 19
    HMAC_WITH_SHA256 = 20
    HMAC_WITH_SHA384 = 21
    HMAC_WITH_SHA512 = 22
    EC_GENERIC_KEY = 23
    EC_DOMAIN_SECP256R1 = 24
    COMPOUND_KEY = 25
    HYBRID_KEY = 26
    FALCON = 27
    ROUND5_ND_5KEM_5D = 28
    RANDOM_PADDING = 29
