/**
 * Copyright (C) 2015-2019 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * (1) Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * (3) Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */


const initFoundationInterfaceTag = (Module, modules) => {
    const FoundationInterfaceTag = Object.freeze({

        ALG: 1,

        ALG_INFO: 2,

        ALG_INFO_DESERIALIZER: 3,

        ALG_INFO_SERIALIZER: 4,

        ASN1_READER: 5,

        ASN1_WRITER: 6,

        AUTH_DECRYPT: 7,

        AUTH_ENCRYPT: 8,

        CIPHER: 9,

        CIPHER_AUTH: 10,

        CIPHER_AUTH_INFO: 11,

        CIPHER_INFO: 12,

        COMPUTE_SHARED_KEY: 13,

        DECRYPT: 14,

        ENCRYPT: 15,

        ENTROPY_SOURCE: 16,

        HASH: 17,

        KDF: 18,

        KEY: 19,

        KEY_ALG: 20,

        KEY_CIPHER: 21,

        KEY_DESERIALIZER: 22,

        KEY_SERIALIZER: 23,

        KEY_SIGNER: 24,

        MAC: 25,

        MESSAGE_INFO_FOOTER_SERIALIZER: 26,

        MESSAGE_INFO_SERIALIZER: 27,

        PADDING: 28,

        PRIVATE_KEY: 29,

        PUBLIC_KEY: 30,

        RANDOM: 31,

        SALTED_KDF: 32
    });

    return FoundationInterfaceTag;
};

module.exports = initFoundationInterfaceTag;
