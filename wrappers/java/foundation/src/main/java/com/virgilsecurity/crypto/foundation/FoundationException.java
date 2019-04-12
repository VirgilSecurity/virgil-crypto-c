/*
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

package com.virgilsecurity.crypto.foundation;

/*
* Defines the library status codes.
*/
public class FoundationException extends RuntimeException {

    public static final int SUCCESS = 0;

    public static final int ERROR_BAD_ARGUMENTS = -1;

    public static final int ERROR_UNINITIALIZED = -2;

    public static final int ERROR_UNHANDLED_THIRDPARTY_ERROR = -3;

    public static final int ERROR_SMALL_BUFFER = -101;

    public static final int ERROR_UNSUPPORTED_ALGORITHM = -200;

    public static final int ERROR_AUTH_FAILED = -201;

    public static final int ERROR_OUT_OF_DATA = -202;

    public static final int ERROR_BAD_ASN1 = -203;

    public static final int ERROR_ASN1_LOSSY_TYPE_NARROWING = -204;

    public static final int ERROR_BAD_PKCS1_PUBLIC_KEY = -205;

    public static final int ERROR_BAD_PKCS1_PRIVATE_KEY = -206;

    public static final int ERROR_BAD_PKCS8_PUBLIC_KEY = -207;

    public static final int ERROR_BAD_PKCS8_PRIVATE_KEY = -208;

    public static final int ERROR_BAD_ENCRYPTED_DATA = -209;

    public static final int ERROR_RANDOM_FAILED = -210;

    public static final int ERROR_KEY_GENERATION_FAILED = -211;

    public static final int ERROR_ENTROPY_SOURCE_FAILED = -212;

    public static final int ERROR_RNG_REQUESTED_DATA_TOO_BIG = -213;

    public static final int ERROR_BAD_BASE64 = -214;

    public static final int ERROR_BAD_PEM = -215;

    public static final int ERROR_SHARED_KEY_EXCHANGE_FAILED = -216;

    public static final int ERROR_BAD_ED25519_PUBLIC_KEY = -217;

    public static final int ERROR_BAD_ED25519_PRIVATE_KEY = -218;

    public static final int ERROR_BAD_CURVE25519_PUBLIC_KEY = -219;

    public static final int ERROR_BAD_CURVE25519_PRIVATE_KEY = -220;

    public static final int ERROR_NO_MESSAGE_INFO = -301;

    public static final int ERROR_BAD_MESSAGE_INFO = -302;

    public static final int ERROR_KEY_RECIPIENT_IS_NOT_FOUND = -303;

    public static final int ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG = -304;

    public static final int ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG = -305;

    public static final int ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND = -306;

    public static final int ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH = -307;

    public static final int ERROR_BAD_SIGNATURE = -308;

    private int statusCode;

    /* Create new instance. */
    public FoundationException(int statusCode) {
        super();
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return this.statusCode;
    }
}

