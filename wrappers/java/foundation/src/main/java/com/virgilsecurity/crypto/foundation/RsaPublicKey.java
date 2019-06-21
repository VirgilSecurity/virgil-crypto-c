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

public class RsaPublicKey implements AutoCloseable, Alg, Key, Encrypt, VerifyHash, PublicKey, GenerateEphemeralKey {

    public long cCtx;

    /* Create underlying C context. */
    public RsaPublicKey() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.rsaPublicKey_new();
    }

    public void setHash(Hash hash) {
        FoundationJNI.INSTANCE.rsaPublicKey_setHash(this.cCtx, hash);
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.rsaPublicKey_setRandom(this.cCtx, random);
    }

    public void setAsn1rd(Asn1Reader asn1rd) {
        FoundationJNI.INSTANCE.rsaPublicKey_setAsn1rd(this.cCtx, asn1rd);
    }

    public void setAsn1wr(Asn1Writer asn1wr) {
        FoundationJNI.INSTANCE.rsaPublicKey_setAsn1wr(this.cCtx, asn1wr);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.rsaPublicKey_setupDefaults(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static RsaPublicKey getInstance(long cCtx) {
        RsaPublicKey newInstance = new RsaPublicKey();
        newInstance.cCtx = cCtx;
        return newInstance;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.rsaPublicKey_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.rsaPublicKey_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.rsaPublicKey_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.rsaPublicKey_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Length of the key in bytes.
    */
    public int keyLen() {
        return FoundationJNI.INSTANCE.rsaPublicKey_keyLen(this.cCtx);
    }

    /*
    * Length of the key in bits.
    */
    public int keyBitlen() {
        return FoundationJNI.INSTANCE.rsaPublicKey_keyBitlen(this.cCtx);
    }

    /*
    * Encrypt given data.
    */
    public byte[] encrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.rsaPublicKey_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.rsaPublicKey_encryptedLen(this.cCtx, dataLen);
    }

    /*
    * Verify data with given public key and signature.
    */
    public boolean verifyHash(byte[] hashDigest, AlgId hashId, byte[] signature) {
        return FoundationJNI.INSTANCE.rsaPublicKey_verifyHash(this.cCtx, hashDigest, hashId, signature);
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
    * Export public key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public byte[] exportPublicKey() throws FoundationException {
        return FoundationJNI.INSTANCE.rsaPublicKey_exportPublicKey(this.cCtx);
    }

    /*
    * Return length in bytes required to hold exported public key.
    */
    public int exportedPublicKeyLen() {
        return FoundationJNI.INSTANCE.rsaPublicKey_exportedPublicKeyLen(this.cCtx);
    }

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public void importPublicKey(byte[] data) throws FoundationException {
        FoundationJNI.INSTANCE.rsaPublicKey_importPublicKey(this.cCtx, data);
    }

    /*
    * Generate ephemeral private key of the same type.
    */
    public PrivateKey generateEphemeralKey() throws FoundationException {
        return FoundationJNI.INSTANCE.rsaPublicKey_generateEphemeralKey(this.cCtx);
    }
}

