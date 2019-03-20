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
* Create algorithms based on the given information.
*/
public class AlgFactory {

    /*
    * Create algorithm that implements "hash stream" interface.
    */
    public static Hash createHashFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createHashFromInfo(algInfo);
    }

    /*
    * Create algorithm that implements "mac stream" interface.
    */
    public static Mac createMacFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createMacFromInfo(algInfo);
    }

    /*
    * Create algorithm that implements "kdf" interface.
    */
    public static Kdf createKdfFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createKdfFromInfo(algInfo);
    }

    /*
    * Create algorithm that implements "salted kdf" interface.
    */
    public static SaltedKdf createSaltedKdfFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createSaltedKdfFromInfo(algInfo);
    }

    /*
    * Create algorithm that implements "cipher" interface.
    */
    public static Cipher createCipherFromInfo(AlgInfo algInfo) {
        return FoundationJNI.INSTANCE.algFactory_createCipherFromInfo(algInfo);
    }

    /*
    * Create algorithm that implements "public key" interface.
    */
    public static PublicKey createPublicKeyFromRawKey(RawKey rawKey) {
        return FoundationJNI.INSTANCE.algFactory_createPublicKeyFromRawKey(rawKey);
    }

    /*
    * Create algorithm that implements "private key" interface.
    */
    public static PrivateKey createPrivateKeyFromRawKey(RawKey rawKey) {
        return FoundationJNI.INSTANCE.algFactory_createPrivateKeyFromRawKey(rawKey);
    }
}

