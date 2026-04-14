/*
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

package com.virgilsecurity.crypto.foundation;

public class OidId {

    public static final int NONE = 0;
    public static final int RSA = 1;
    public static final int ED25519 = 2;
    public static final int CURVE25519 = 3;
    public static final int SHA224 = 4;
    public static final int SHA256 = 5;
    public static final int SHA384 = 6;
    public static final int SHA512 = 7;
    public static final int KDF1 = 8;
    public static final int KDF2 = 9;
    public static final int AES256_GCM = 10;
    public static final int AES256_CBC = 11;
    public static final int PKCS5_PBKDF2 = 12;
    public static final int PKCS5_PBES2 = 13;
    public static final int CMS_DATA = 14;
    public static final int CMS_ENVELOPED_DATA = 15;
    public static final int HKDF_WITH_SHA256 = 16;
    public static final int HKDF_WITH_SHA384 = 17;
    public static final int HKDF_WITH_SHA512 = 18;
    public static final int HMAC_WITH_SHA224 = 19;
    public static final int HMAC_WITH_SHA256 = 20;
    public static final int HMAC_WITH_SHA384 = 21;
    public static final int HMAC_WITH_SHA512 = 22;
    public static final int EC_GENERIC_KEY = 23;
    public static final int EC_DOMAIN_SECP256R1 = 24;
    public static final int COMPOUND_KEY = 25;
    public static final int HYBRID_KEY = 26;
    public static final int FALCON = 27;
    public static final int ROUND5_ND_1CCA_5D = 28;
    public static final int RANDOM_PADDING = 29;

    private final int code;

    public OidId(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }
}
