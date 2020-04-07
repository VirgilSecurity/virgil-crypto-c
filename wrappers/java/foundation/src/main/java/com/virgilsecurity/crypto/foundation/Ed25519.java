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
* This is implementation of Ed25519 elliptic curve algorithms.
*/
public class Ed25519 implements AutoCloseable, KeyAlg, KeyCipher, KeySigner, ComputeSharedKey, Kem {

    public long cCtx;

    /* Create underlying C context. */
    public Ed25519() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.ed25519_new();
    }

    /* Wrap underlying C context. */
    Ed25519(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.ed25519_setRandom(this.cCtx, random);
    }

    public void setEcies(Ecies ecies) {
        FoundationJNI.INSTANCE.ed25519_setEcies(this.cCtx, ecies);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.ed25519_setupDefaults(this.cCtx);
    }

    /*
    * Generate new private key.
    * Note, this operation might be slow.
    */
    public PrivateKey generateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_generateKey(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Ed25519 getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Ed25519(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.ed25519_close(ctx);
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
        return FoundationJNI.INSTANCE.ed25519_generateEphemeralKey(this.cCtx, key);
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
        return FoundationJNI.INSTANCE.ed25519_importPublicKey(this.cCtx, rawKey);
    }

    /*
    * Import public key from the raw binary format.
    */
    public PublicKey importPublicKeyData(byte[] keyData, AlgInfo keyAlgInfo) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_importPublicKeyData(this.cCtx, keyData, keyAlgInfo);
    }

    /*
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public RawPublicKey exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_exportPublicKey(this.cCtx, publicKey);
    }

    /*
    * Return length in bytes required to hold exported public key.
    */
    public int exportedPublicKeyDataLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.ed25519_exportedPublicKeyDataLen(this.cCtx, publicKey);
    }

    /*
    * Export public key to the raw binary format without algorithm information.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    */
    public byte[] exportPublicKeyData(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_exportPublicKeyData(this.cCtx, publicKey);
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
        return FoundationJNI.INSTANCE.ed25519_importPrivateKey(this.cCtx, rawKey);
    }

    /*
    * Import private key from the raw binary format.
    */
    public PrivateKey importPrivateKeyData(byte[] keyData, AlgInfo keyAlgInfo) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_importPrivateKeyData(this.cCtx, keyData, keyAlgInfo);
    }

    /*
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public RawPrivateKey exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_exportPrivateKey(this.cCtx, privateKey);
    }

    /*
    * Return length in bytes required to hold exported private key.
    */
    public int exportedPrivateKeyDataLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.ed25519_exportedPrivateKeyDataLen(this.cCtx, privateKey);
    }

    /*
    * Export private key to the raw binary format without algorithm information.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    */
    public byte[] exportPrivateKeyData(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_exportPrivateKeyData(this.cCtx, privateKey);
    }

    /*
    * Check if algorithm can encrypt data with a given key.
    */
    public boolean canEncrypt(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.ed25519_canEncrypt(this.cCtx, publicKey, dataLen);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.ed25519_encryptedLen(this.cCtx, publicKey, dataLen);
    }

    /*
    * Encrypt data with a given public key.
    */
    public byte[] encrypt(PublicKey publicKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_encrypt(this.cCtx, publicKey, data);
    }

    /*
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    */
    public boolean canDecrypt(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.ed25519_canDecrypt(this.cCtx, privateKey, dataLen);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public int decryptedLen(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.ed25519_decryptedLen(this.cCtx, privateKey, dataLen);
    }

    /*
    * Decrypt given data.
    */
    public byte[] decrypt(PrivateKey privateKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_decrypt(this.cCtx, privateKey, data);
    }

    /*
    * Check if algorithm can sign data digest with a given key.
    */
    public boolean canSign(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.ed25519_canSign(this.cCtx, privateKey);
    }

    /*
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    */
    public int signatureLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.ed25519_signatureLen(this.cCtx, privateKey);
    }

    /*
    * Sign data digest with a given private key.
    */
    public byte[] signHash(PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_signHash(this.cCtx, privateKey, hashId, digest);
    }

    /*
    * Check if algorithm can verify data digest with a given key.
    */
    public boolean canVerify(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.ed25519_canVerify(this.cCtx, publicKey);
    }

    /*
    * Verify data digest with a given public key and signature.
    */
    public boolean verifyHash(PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature) {
        return FoundationJNI.INSTANCE.ed25519_verifyHash(this.cCtx, publicKey, hashId, digest, signature);
    }

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    public byte[] computeSharedKey(PublicKey publicKey, PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_computeSharedKey(this.cCtx, publicKey, privateKey);
    }

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    public int sharedKeyLen(Key key) {
        return FoundationJNI.INSTANCE.ed25519_sharedKeyLen(this.cCtx, key);
    }

    /*
    * Return length in bytes required to hold encapsulated shared key.
    */
    public int kemSharedKeyLen(Key key) {
        return FoundationJNI.INSTANCE.ed25519_kemSharedKeyLen(this.cCtx, key);
    }

    /*
    * Return length in bytes required to hold encapsulated key.
    */
    public int kemEncapsulatedKeyLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.ed25519_kemEncapsulatedKeyLen(this.cCtx, publicKey);
    }

    /*
    * Generate a shared key and a key encapsulated message.
    */
    public KemKemEncapsulateResult kemEncapsulate(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_kemEncapsulate(this.cCtx, publicKey);
    }

    /*
    * Decapsulate the shared key.
    */
    public byte[] kemDecapsulate(byte[] encapsulatedKey, PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.ed25519_kemDecapsulate(this.cCtx, encapsulatedKey, privateKey);
    }
}

