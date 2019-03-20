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

package virgil.crypto.foundation;

/*
* Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
*/
public class Base64 {

    /*
    * Calculate length in bytes required to hold an encoded base64 string.
    */
    public static int encodedLen(int dataLen) {
        return FoundationJNI.INSTANCE.base64_encodedLen(dataLen);
    }

    /*
    * Encode given data to the base64 format.
    * Note, written buffer is NOT null-terminated.
    */
    public static byte[] encode(byte[] data) {
        return FoundationJNI.INSTANCE.base64_encode(data);
    }

    /*
    * Calculate length in bytes required to hold a decoded base64 string.
    */
    public static int decodedLen(int strLen) {
        return FoundationJNI.INSTANCE.base64_decodedLen(strLen);
    }

    /*
    * Decode given data from the base64 format.
    */
    public static byte[] decode(byte[] str) throws FoundationException {
        return FoundationJNI.INSTANCE.base64_decode(str);
    }
}

