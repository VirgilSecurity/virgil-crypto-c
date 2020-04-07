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
* Provide post-quantum encryption based on the round5 implementation.
* For algorithm details check https://github.com/round5/code
*/
public class Round5 implements AutoCloseable, KeyAlg, Kem {

    public long cCtx;

    /* Create underlying C context. */
    public Round5() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.round5_new();
    }

    /* Wrap underlying C context. */
    Round5(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.round5_setRandom(this.cCtx, random);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.round5_setupDefaults(this.cCtx);
    }

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public PrivateKey generateKey(AlgId algId) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_generateKey(this.cCtx, algId);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Round5 getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Round5(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.round5_close(ctx);
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

    /*
    * Defines whether a public key can be imported or not.
    */
    public boolean getCanImportPublicKey() {
        return true;
    }

    /*
    * Define whether a public key can be exported or not.
    */
    public boolean getCanExportPublicKey() {
        return true;
    }

    /*
    * Define whether a private key can be imported or not.
    */
    public boolean getCanImportPrivateKey() {
        return true;
    }

    /*
    * Define whether a private key can be exported or not.
    */
    public boolean getCanExportPrivateKey() {
        return true;
    }

    /*
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    */
    public PrivateKey generateEphemeralKey(Key key) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_generateEphemeralKey(this.cCtx, key);
    }

    /*
    * Import public key from the raw binary format.
    *
    * Return public key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public PublicKey importPublicKey(RawPublicKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_importPublicKey(this.cCtx, rawKey);
    }

    /*
    * Import public key from the raw binary format.
    */
    public PublicKey importPublicKeyData(byte[] keyData, AlgInfo keyAlgInfo) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_importPublicKeyData(this.cCtx, keyData, keyAlgInfo);
    }

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public RawPublicKey exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_exportPublicKey(this.cCtx, publicKey);
    }

    /*
    * Return length in bytes required to hold exported public key.
    */
    public int exportedPublicKeyDataLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.round5_exportedPublicKeyDataLen(this.cCtx, publicKey);
    }

    /*
    * Export public key to the raw binary format without algorithm information.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public byte[] exportPublicKeyData(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_exportPublicKeyData(this.cCtx, publicKey);
    }

    /*
    * Import private key from the raw binary format.
    *
    * Return private key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public PrivateKey importPrivateKey(RawPrivateKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_importPrivateKey(this.cCtx, rawKey);
    }

    /*
    * Import private key from the raw binary format.
    */
    public PrivateKey importPrivateKeyData(byte[] keyData, AlgInfo keyAlgInfo) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_importPrivateKeyData(this.cCtx, keyData, keyAlgInfo);
    }

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public RawPrivateKey exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_exportPrivateKey(this.cCtx, privateKey);
    }

    /*
    * Return length in bytes required to hold exported private key.
    */
    public int exportedPrivateKeyDataLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.round5_exportedPrivateKeyDataLen(this.cCtx, privateKey);
    }

    /*
    * Export private key to the raw binary format without algorithm information.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public byte[] exportPrivateKeyData(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_exportPrivateKeyData(this.cCtx, privateKey);
    }

    /*
    * Return length in bytes required to hold encapsulated shared key.
    */
    public int kemSharedKeyLen(Key key) {
        return FoundationJNI.INSTANCE.round5_kemSharedKeyLen(this.cCtx, key);
    }

    /*
    * Return length in bytes required to hold encapsulated key.
    */
    public int kemEncapsulatedKeyLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.round5_kemEncapsulatedKeyLen(this.cCtx, publicKey);
    }

    /*
    * Generate a shared key and a key encapsulated message.
    */
    public KemKemEncapsulateResult kemEncapsulate(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_kemEncapsulate(this.cCtx, publicKey);
    }

    /*
    * Decapsulate the shared key.
    */
    public byte[] kemDecapsulate(byte[] encapsulatedKey, PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.round5_kemDecapsulate(this.cCtx, encapsulatedKey, privateKey);
    }
}

