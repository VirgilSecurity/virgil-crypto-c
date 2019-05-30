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
* This is implementation of CURVE25519 public key
*/
public class Curve25519PublicKey implements AutoCloseable, Alg, Key, Encrypt, PublicKey, GenerateEphemeralKey {

    public long cCtx;

    /* Create underlying C context. */
    public Curve25519PublicKey() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.curve25519PublicKey_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public Curve25519PublicKey(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.curve25519PublicKey_setRandom(this.cCtx, random);
    }

    public void setEcies(Ecies ecies) {
        FoundationJNI.INSTANCE.curve25519PublicKey_setEcies(this.cCtx, ecies);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.curve25519PublicKey_setupDefaults(this.cCtx);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.curve25519PublicKey_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.curve25519PublicKey_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.curve25519PublicKey_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.curve25519PublicKey_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Length of the key in bytes.
    */
    public int keyLen() {
        return FoundationJNI.INSTANCE.curve25519PublicKey_keyLen(this.cCtx);
    }

    /*
    * Length of the key in bits.
    */
    public int keyBitlen() {
        return FoundationJNI.INSTANCE.curve25519PublicKey_keyBitlen(this.cCtx);
    }

    /*
    * Encrypt given data.
    */
    public byte[] encrypt(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519PublicKey_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.curve25519PublicKey_encryptedLen(this.cCtx, dataLen);
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
        return FoundationJNI.INSTANCE.curve25519PublicKey_exportPublicKey(this.cCtx);
    }

    /*
    * Return length in bytes required to hold exported public key.
    */
    public int exportedPublicKeyLen() {
        return FoundationJNI.INSTANCE.curve25519PublicKey_exportedPublicKeyLen(this.cCtx);
    }

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public void importPublicKey(byte[] data) throws FoundationException {
        FoundationJNI.INSTANCE.curve25519PublicKey_importPublicKey(this.cCtx, data);
    }

    /*
    * Generate ephemeral private key of the same type.
    */
    public PrivateKey generateEphemeralKey() throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519PublicKey_generateEphemeralKey(this.cCtx);
    }
}

