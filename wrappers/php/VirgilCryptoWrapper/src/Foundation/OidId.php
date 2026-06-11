<?php
/**
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
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

namespace Virgil\CryptoWrapper\Foundation;

class OidId extends Enum
{

    private const NONE = 0;
    private const RSA = 1;
    private const ED25519 = 2;
    private const CURVE25519 = 3;
    private const SHA224 = 4;
    private const SHA256 = 5;
    private const SHA384 = 6;
    private const SHA512 = 7;
    private const KDF1 = 8;
    private const KDF2 = 9;
    private const AES256_GCM = 10;
    private const AES256_CBC = 11;
    private const AES128_KW = 12;
    private const AES192_KW = 13;
    private const AES256_KW = 14;
    private const PKCS5_PBKDF2 = 15;
    private const PKCS5_PBES2 = 16;
    private const CMS_DATA = 17;
    private const CMS_ENVELOPED_DATA = 18;
    private const HKDF_WITH_SHA256 = 19;
    private const HKDF_WITH_SHA384 = 20;
    private const HKDF_WITH_SHA512 = 21;
    private const HMAC_WITH_SHA224 = 22;
    private const HMAC_WITH_SHA256 = 23;
    private const HMAC_WITH_SHA384 = 24;
    private const HMAC_WITH_SHA512 = 25;
    private const EC_GENERIC_KEY = 26;
    private const EC_DOMAIN_SECP256R1 = 27;
    private const COMPOUND_KEY = 28;
    private const HYBRID_KEY = 29;
    private const FALCON = 30;
    private const RANDOM_PADDING = 31;
    private const ML_KEM_768 = 32;
    private const ML_DSA_65 = 33;

}
