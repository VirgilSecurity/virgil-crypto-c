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

public class AlgFactory {

    public static Hash createHashFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createHashFromInfo(algInfo);
    }

    public static Mac createMacFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createMacFromInfo(algInfo);
    }

    public static Kdf createKdfFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createKdfFromInfo(algInfo);
    }

    public static SaltedKdf createSaltedKdfFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createSaltedKdfFromInfo(algInfo);
    }

    public static Cipher createCipherFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createCipherFromInfo(algInfo);
    }

    public static Padding createPaddingFromInfo(AlgInfo algInfo, Random random) {
        return FoundationJNI.INSTANCE.algFactory_createPaddingFromInfo(algInfo, random);
    }

}
