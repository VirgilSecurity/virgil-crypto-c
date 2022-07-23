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

    /* Wrap underlying C context. */
    KeyProvider(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static KeyProvider getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new KeyProvider(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.keyProvider_close(ctx);
        }
    }

    /* Close resource. */
    public void close() {
        clearResources();
    }

    /* Finalize resource. */
    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.keyProvider_setRandom(this.cCtx, random);
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
    * Generate new private key with a given algorithm.
    */
    public PrivateKey generatePrivateKey(AlgId algId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generatePrivateKey(this.cCtx, algId);
    }

    /*
    * Generate new post-quantum private key with default algorithms.
    * Note, that a post-quantum key combines classic private keys
    * alongside with post-quantum private keys.
    * Current structure is "compound private key" is:
    * - cipher private key is "hybrid private key" where:
    * - first key is a classic private key;
    * - second key is a post-quantum private key;
    * - signer private key "hybrid private key" where:
    * - first key is a classic private key;
    * - second key is a post-quantum private key.
    */
    public PrivateKey generatePostQuantumPrivateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generatePostQuantumPrivateKey(this.cCtx);
    }

    /*
    * Generate new compound private key with given algorithms.
    */
    public PrivateKey generateCompoundPrivateKey(AlgId cipherAlgId, AlgId signerAlgId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generateCompoundPrivateKey(this.cCtx, cipherAlgId, signerAlgId);
    }

    /*
    * Generate new hybrid private key with given algorithms.
    */
    public PrivateKey generateHybridPrivateKey(AlgId firstKeyAlgId, AlgId secondKeyAlgId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generateHybridPrivateKey(this.cCtx, firstKeyAlgId, secondKeyAlgId);
    }

    /*
    * Generate new compound private key with nested hybrid private keys.
    *
    * Note, second key algorithm identifiers can be NONE, in this case,
    * a regular key will be crated instead of a hybrid key.
    */
    public PrivateKey generateCompoundHybridPrivateKey(AlgId cipherFirstKeyAlgId, AlgId cipherSecondKeyAlgId, AlgId signerFirstKeyAlgId, AlgId signerSecondKeyAlgId) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_generateCompoundHybridPrivateKey(this.cCtx, cipherFirstKeyAlgId, cipherSecondKeyAlgId, signerFirstKeyAlgId, signerSecondKeyAlgId);
    }

    /*
    * Import private key from the PKCS#8 format.
    */
    public PrivateKey importPrivateKey(byte[] keyData) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_importPrivateKey(this.cCtx, keyData);
    }

    /*
    * Import public key from the PKCS#8 format.
    */
    public PublicKey importPublicKey(byte[] keyData) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_importPublicKey(this.cCtx, keyData);
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
    * Export given private key to the PKCS#8 or SEC1 DER format.
    *
    * Precondition: private key must be exportable.
    */
    public byte[] exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.keyProvider_exportPrivateKey(this.cCtx, privateKey);
    }
}

