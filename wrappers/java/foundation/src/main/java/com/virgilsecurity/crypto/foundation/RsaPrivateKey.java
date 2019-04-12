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

public class RsaPrivateKey implements AutoCloseable, Alg, Key, GenerateKey, Decrypt, SignHash, PrivateKey {

    public long cCtx;

    /* Create underlying C context. */
    public RsaPrivateKey() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.rsaPrivateKey_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public RsaPrivateKey(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.rsaPrivateKey_setRandom(this.cCtx, random);
    }

    public void setAsn1rd(Asn1Reader asn1rd) {
        FoundationJNI.INSTANCE.rsaPrivateKey_setAsn1rd(this.cCtx, asn1rd);
    }

    public void setAsn1wr(Asn1Writer asn1wr) {
        FoundationJNI.INSTANCE.rsaPrivateKey_setAsn1wr(this.cCtx, asn1wr);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.rsaPrivateKey_setupDefaults(this.cCtx);
    }

    /*
    * Setup key length in bits that is used for key generation.
    */
    public void setKeygenParams(int bitlen) {
        FoundationJNI.INSTANCE.rsaPrivateKey_setKeygenParams(this.cCtx, bitlen);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.rsaPrivateKey_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.rsaPrivateKey_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.rsaPrivateKey_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.rsaPrivateKey_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Length of the key in bytes.
    */
    public int keyLen() {
        return FoundationJNI.INSTANCE.rsaPrivateKey_keyLen(this.cCtx);
    }

    /*
    * Length of the key in bits.
    */
    public int keyBitlen() {
        return FoundationJNI.INSTANCE.rsaPrivateKey_keyBitlen(this.cCtx);
    }

    /*
    * Generate new private or secret key.
    * Note, this operation can be slow.
    */
    public void generateKey() throws FoundationException {
        FoundationJNI.INSTANCE.rsaPrivateKey_generateKey(this.cCtx);
    }

    /*
    * Decrypt given data.
    */
    public byte[] decrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.rsaPrivateKey_decrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public int decryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.rsaPrivateKey_decryptedLen(this.cCtx, dataLen);
    }

    /*
    * Return length in bytes required to hold signature.
    */
    public int signatureLen() {
        return FoundationJNI.INSTANCE.rsaPrivateKey_signatureLen(this.cCtx);
    }

    /*
    * Sign data given private key.
    */
    public byte[] signHash(byte[] hashDigest, AlgId hashId) throws FoundationException {
        return FoundationJNI.INSTANCE.rsaPrivateKey_signHash(this.cCtx, hashDigest, hashId);
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
    * Extract public part of the key.
    */
    public PublicKey extractPublicKey() {
        return FoundationJNI.INSTANCE.rsaPrivateKey_extractPublicKey(this.cCtx);
    }

    /*
    * Export private key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public byte[] exportPrivateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.rsaPrivateKey_exportPrivateKey(this.cCtx);
    }

    /*
    * Return length in bytes required to hold exported private key.
    */
    public int exportedPrivateKeyLen() {
        return FoundationJNI.INSTANCE.rsaPrivateKey_exportedPrivateKeyLen(this.cCtx);
    }

    /*
    * Import private key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public void importPrivateKey(byte[] data) throws FoundationException {
        FoundationJNI.INSTANCE.rsaPrivateKey_importPrivateKey(this.cCtx, data);
    }
}

