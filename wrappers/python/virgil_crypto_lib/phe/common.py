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


class Common(object):

    # PHE elliptic curve point binary length
    PHE_POINT_LENGTH = 65
    # PHE max password length
    PHE_MAX_PASSWORD_LENGTH = 128
    # PHE server identifier length
    PHE_SERVER_IDENTIFIER_LENGTH = 32
    # PHE client identifier length
    PHE_CLIENT_IDENTIFIER_LENGTH = 32
    # PHE account key length
    PHE_ACCOUNT_KEY_LENGTH = 32
    # PHE private key length
    PHE_PRIVATE_KEY_LENGTH = 32
    # PHE public key length
    PHE_PUBLIC_KEY_LENGTH = 65
    # PHE hash length
    PHE_HASH_LEN = 32
    # Maximum data size to encrypt
    PHE_MAX_ENCRYPT_LEN = 1024 * 1024 - 64
    # Maximum data size to decrypt
    PHE_MAX_DECRYPT_LEN = 1024 * 1024
