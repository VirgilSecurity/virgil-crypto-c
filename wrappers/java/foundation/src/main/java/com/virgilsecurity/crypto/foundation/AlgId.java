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

public class AlgId {

    public static final int NONE = 0;
    public static final int SHA224 = 1;
    public static final int SHA256 = 2;
    public static final int SHA384 = 3;
    public static final int SHA512 = 4;
    public static final int KDF1 = 5;
    public static final int KDF2 = 6;
    public static final int RSA = 7;
    public static final int ED25519 = 8;
    public static final int CURVE25519 = 9;
    public static final int SECP256R1 = 10;
    public static final int AES256_GCM = 11;
    public static final int AES256_CBC = 12;
    public static final int HMAC = 13;
    public static final int HKDF = 14;
    public static final int PKCS5_PBKDF2 = 15;
    public static final int PKCS5_PBES2 = 16;
    public static final int COMPOUND_KEY = 17;
    public static final int HYBRID_KEY = 18;
    public static final int FALCON = 19;
    public static final int ROUND5_ND_1CCA_5D = 20;
    public static final int RANDOM_PADDING = 21;

    private final int code;

    public AlgId(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }
}
