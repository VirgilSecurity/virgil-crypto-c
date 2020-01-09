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
* Create a bridge between "raw keys" and algorithms that can import them.
*/
public class KeyAlgFactory {

    /*
    * Create a key algorithm based on an identifier.
    */
    public static KeyAlg createFromAlgId(AlgId algId, Random random) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAlgFactory_createFromAlgId(algId, random);
    }

    /*
    * Create a key algorithm correspond to a specific key.
    */
    public static KeyAlg createFromKey(Key key, Random random) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAlgFactory_createFromKey(key, random);
    }

    /*
    * Create a key algorithm that can import "raw public key".
    */
    public static KeyAlg createFromRawPublicKey(RawPublicKey publicKey, Random random) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAlgFactory_createFromRawPublicKey(publicKey, random);
    }

    /*
    * Create a key algorithm that can import "raw private key".
    */
    public static KeyAlg createFromRawPrivateKey(RawPrivateKey privateKey, Random random) throws FoundationException {
        return FoundationJNI.INSTANCE.keyAlgFactory_createFromRawPrivateKey(privateKey, random);
    }
}

