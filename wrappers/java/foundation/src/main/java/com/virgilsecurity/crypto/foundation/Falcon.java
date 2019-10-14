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
* Provide post-quantum signature based on the falcon implementation.
* For algorithm details check https://falcon-sign.info.
*/
public class Falcon implements AutoCloseable, Alg, KeyAlg, KeySigner {

    public long cCtx;

    /* Create underlying C context. */
    public Falcon() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.falcon_new();
    }

    /* Wrap underlying C context. */
    Falcon(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public int getSeedLen() {
        return 48;
    }

    public int getLogn512() {
        return 9;
    }

    public int getLogn1024() {
        return 10;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.falcon_setRandom(this.cCtx, random);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.falcon_setupDefaults(this.cCtx);
    }

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public PrivateKey generateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.falcon_generateKey(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Falcon getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Falcon(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.falcon_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.falcon_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.falcon_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.falcon_restoreAlgInfo(this.cCtx, algInfo);
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
        return FoundationJNI.INSTANCE.falcon_generateEphemeralKey(this.cCtx, key);
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
        return FoundationJNI.INSTANCE.falcon_importPublicKey(this.cCtx, rawKey);
    }

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public RawPublicKey exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.falcon_exportPublicKey(this.cCtx, publicKey);
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
        return FoundationJNI.INSTANCE.falcon_importPrivateKey(this.cCtx, rawKey);
    }

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public RawPrivateKey exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.falcon_exportPrivateKey(this.cCtx, privateKey);
    }

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public boolean canSign(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.falcon_canSign(this.cCtx, privateKey);
    }

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public int signatureLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.falcon_signatureLen(this.cCtx, privateKey);
    }

    /*
    * Sign data digest with a given private key.
    */
    public byte[] signHash(PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException {
        return FoundationJNI.INSTANCE.falcon_signHash(this.cCtx, privateKey, hashId, digest);
    }

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public boolean canVerify(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.falcon_canVerify(this.cCtx, publicKey);
    }

    /*
    * Verify data digest with a given public key and signature.
    */
    public boolean verifyHash(PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature) {
        return FoundationJNI.INSTANCE.falcon_verifyHash(this.cCtx, publicKey, hashId, digest, signature);
    }
}

