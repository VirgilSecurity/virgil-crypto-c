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
* Provide functionality for private key generation and importing that
* relies on the software default implementations.
*/
public class KeyProvider implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public KeyProvider() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyProvider_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public KeyProvider(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.keyProvider_close(this.cCtx);
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.keyProvider_setRandom(this.cCtx, random);
    }

    public void setEcies(Ecies ecies) {
        FoundationJNI.INSTANCE.keyProvider_setEcies(this.cCtx, ecies);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.keyProvider_setupDefaults(this.cCtx);
    }

    /*
    * Setup parameters that is used during RSA key generation.
    */
    public void setRsaParams(int bitlen) {
        FoundationJNI.INSTANCE.keyProvider_setRsaParams(this.cCtx, bitlen);
    }

    /*
    * Generate new private key from the given id.
    */
    public PrivateKey generatePrivateKey(AlgId algId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generatePrivateKey(this.cCtx, algId);
    }

    /*
    * Import private key from the PKCS#8 format.
    */
    public PrivateKey importPrivateKey(byte[] pkcs8Data) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_importPrivateKey(this.cCtx, pkcs8Data);
    }

    /*
    * Import public key from the PKCS#8 format.
    */
    public PublicKey importPublicKey(byte[] pkcs8Data) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_importPublicKey(this.cCtx, pkcs8Data);
    }

    /*
    * Calculate buffer size enough to hold exported public key.
    *
    * Precondition: public key must be exportable.
    */
    public int exportedPublicKeyLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.keyProvider_exportedPublicKeyLen(this.cCtx, publicKey);
    }

    /*
    * Export given public key to the PKCS#8 DER format.
    *
    * Precondition: public key must be exportable.
    */
    public byte[] exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_exportPublicKey(this.cCtx, publicKey);
    }

    /*
    * Calculate buffer size enough to hold exported private key.
    *
    * Precondition: private key must be exportable.
    */
    public int exportedPrivateKeyLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.keyProvider_exportedPrivateKeyLen(this.cCtx, privateKey);
    }

    /*
    * Export given private key to the PKCS#8 DER format.
    *
    * Precondition: private key must be exportable.
    */
    public byte[] exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_exportPrivateKey(this.cCtx, privateKey);
    }
}

