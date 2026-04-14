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

public class Curve25519 implements AutoCloseable, KeyAlg, KeyCipher, ComputeSharedKey, Kem {

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.curve25519_setRandom(this.cCtx, random);
    }

    public void setEcies(Ecies ecies) {
        FoundationJNI.INSTANCE.curve25519_setEcies(this.cCtx, ecies);
    }

    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.curve25519_setupDefaults(this.cCtx);
    }

    public PrivateKey generateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_generateKey(this.cCtx);
    }

    public long cCtx;

    public Curve25519() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.curve25519_new();
    }

    package Curve25519(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public Curve25519 getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Curve25519(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.curve25519_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public boolean getCanImportPublicKey() {
        return true;
    }

    public boolean getCanExportPublicKey() {
        return true;
    }

    public boolean getCanImportPrivateKey() {
        return true;
    }

    public boolean getCanExportPrivateKey() {
        return true;
    }

    public PrivateKey generateEphemeralKey(Key key) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_generateEphemeralKey(this.cCtx, key);
    }

    public PublicKey importPublicKey(RawPublicKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_importPublicKey(this.cCtx, rawKey);
    }

    public RawPublicKey exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_exportPublicKey(this.cCtx, publicKey);
    }

    public PrivateKey importPrivateKey(RawPrivateKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_importPrivateKey(this.cCtx, rawKey);
    }

    public RawPrivateKey exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_exportPrivateKey(this.cCtx, privateKey);
    }

    public boolean canEncrypt(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_canEncrypt(this.cCtx, publicKey, dataLen);
    }

    public int encryptedLen(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_encryptedLen(this.cCtx, publicKey, dataLen);
    }

    public byte[] encrypt(PublicKey publicKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_encrypt(this.cCtx, publicKey, data);
    }

    public boolean canDecrypt(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_canDecrypt(this.cCtx, privateKey, dataLen);
    }

    public int decryptedLen(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.curve25519_decryptedLen(this.cCtx, privateKey, dataLen);
    }

    public byte[] decrypt(PrivateKey privateKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_decrypt(this.cCtx, privateKey, data);
    }

    public byte[] computeSharedKey(PublicKey publicKey, PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_computeSharedKey(this.cCtx, publicKey, privateKey);
    }

    public int sharedKeyLen(Key key) {
        return FoundationJNI.INSTANCE.curve25519_sharedKeyLen(this.cCtx, key);
    }

    public int kemSharedKeyLen(Key key) {
        return FoundationJNI.INSTANCE.curve25519_kemSharedKeyLen(this.cCtx, key);
    }

    public int kemEncapsulatedKeyLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.curve25519_kemEncapsulatedKeyLen(this.cCtx, publicKey);
    }

    public KemKemEncapsulateResult kemEncapsulate(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_kemEncapsulate(this.cCtx, publicKey);
    }

    public byte[] kemDecapsulate(byte[] encapsulatedKey, PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.curve25519_kemDecapsulate(this.cCtx, encapsulatedKey, privateKey);
    }

}
