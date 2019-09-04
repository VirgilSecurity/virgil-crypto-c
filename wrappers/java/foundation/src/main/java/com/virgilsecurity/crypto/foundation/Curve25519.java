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
* This is implementation of Curve25519 elliptic curve algorithms.
*/
public class Curve25519 implements AutoCloseable, Alg, KeyAlg, KeyCipher, ComputeSharedKey {

    public java.nio.ByteBuffer cCtx;

    /* Create underlying C context. */
    public Curve25519() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.curve25519_new();
    }

    /* Wrap underlying C context. */
    Curve25519(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.curve25519_setRandom(this.cCtx, random);
    }

    public void setEcies(Ecies ecies) {
        FoundationJNI.INSTANCE.curve25519_setEcies(this.cCtx, ecies);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.curve25519_setupDefaults(this.cCtx);
    }

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public PrivateKey generateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_generateKey(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Curve25519 getInstance(java.nio.ByteBuffer cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Curve25519(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.curve25519_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.curve25519_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.curve25519_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.curve25519_restoreAlgInfo(this.cCtx, algInfo);
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
        return FoundationJNI.INSTANCE.curve25519_generateEphemeralKey(this.cCtx, key);
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
        return FoundationJNI.INSTANCE.curve25519_importPublicKey(this.cCtx, rawKey);
    }

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public RawPublicKey exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_exportPublicKey(this.cCtx, publicKey);
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
        return FoundationJNI.INSTANCE.curve25519_importPrivateKey(this.cCtx, rawKey);
    }

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public RawPrivateKey exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_exportPrivateKey(this.cCtx, privateKey);
    }

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public boolean canEncrypt(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_canEncrypt(this.cCtx, publicKey, dataLen);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_encryptedLen(this.cCtx, publicKey, dataLen);
    }

    /*
    * Encrypt data with a given public key.
    */
    public byte[] encrypt(PublicKey publicKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_encrypt(this.cCtx, publicKey, data);
    }

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public boolean canDecrypt(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_canDecrypt(this.cCtx, privateKey, dataLen);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public int decryptedLen(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_decryptedLen(this.cCtx, privateKey, dataLen);
    }

    /*
    * Decrypt given data.
    */
    public byte[] decrypt(PrivateKey privateKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_decrypt(this.cCtx, privateKey, data);
    }

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public byte[] computeSharedKey(PublicKey publicKey, PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_computeSharedKey(this.cCtx, publicKey, privateKey);
    }

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public int sharedKeyLen(Key key) {
        return FoundationJNI.INSTANCE.curve25519_sharedKeyLen(this.cCtx, key);
    }
}

