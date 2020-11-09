/*
* Copyright (C) 2015-2020 Virgil Security, Inc.
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
* Contains utils for convertion from bytes to HEX and vice-versa.
*/
public class Binary {

    /*
    * Return buffer length enaugh to hold hexed data.
    */
    public static int toHexLen(int dataLen) {
        return FoundationJNI.INSTANCE.binary_toHexLen(dataLen);
    }

    /*
    * Converts byte array to hex.
    * Output length should be twice bigger then input.
    */
    public static String toHex(byte[] data) {
        return FoundationJNI.INSTANCE.binary_toHex(data);
    }

    /*
    * Return buffer length enaugh to hold unhexed data.
    */
    public static int fromHexLen(int hexLen) {
        return FoundationJNI.INSTANCE.binary_fromHexLen(hexLen);
    }

    /*
    * Converts hex string to byte array.
    * Output length should be at least half of the input hex string.
    */
    public static byte[] fromHex(String hexStr) throws FoundationException {
        return FoundationJNI.INSTANCE.binary_fromHex(hexStr);
    }
}

