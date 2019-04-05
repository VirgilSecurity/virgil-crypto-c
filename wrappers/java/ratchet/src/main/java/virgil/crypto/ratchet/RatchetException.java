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

package virgil.crypto.ratchet;

import virgil.crypto.foundation.*;

/*
* Defines the library status codes.
*/
public class RatchetException extends RuntimeException {

    public static final int SUCCESS = 0;

    public static final int ERROR_PROTOBUF_DECODE = -1;

    public static final int ERROR_MESSAGE_VERSION_DOESN_T_MATCH = -2;

    public static final int ERROR_BAD_MESSAGE_TYPE = -3;

    public static final int ERROR_AES = -4;

    public static final int ERROR_RNG_FAILED = -5;

    public static final int ERROR_CURVE25519 = -6;

    public static final int ERROR_KEY_DESERIALIZATION_FAILED = -7;

    public static final int ERROR_INVALID_KEY_TYPE = -8;

    public static final int ERROR_IDENTITY_KEY_DOESNT_MATCH = -9;

    public static final int ERROR_MESSAGE_ALREADY_DECRYPTED = -10;

    public static final int ERROR_TOO_MANY_LOST_MESSAGES = -11;

    public static final int ERROR_SENDER_CHAIN_MISSING = -12;

    public static final int ERROR_SKIPPED_MESSAGE_MISSING = -13;

    public static final int ERROR_CAN_T_ENCRYPT_YET = -14;

    public static final int ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN = -15;

    public static final int ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN = -16;

    public static final int ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN = -17;

    public static final int ERROR_INVALID_PADDING = -18;

    private int statusCode;

    /* Create new instance. */
    public RatchetException(int statusCode) {
        super();
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return this.statusCode;
    }
}

