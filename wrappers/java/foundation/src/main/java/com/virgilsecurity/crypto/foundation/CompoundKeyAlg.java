/*
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
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

public class CompoundKeyAlg implements AutoCloseable, Alg, KeyAlg, KeyCipher, KeySigner {

    public long cCtx;

    public CompoundKeyAlg() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.compoundKeyAlg_new();
    }

    CompoundKeyAlg(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static CompoundKeyAlg getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new CompoundKeyAlg(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.compoundKeyAlg_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.compoundKeyAlg_setRandom(this.cCtx, random);
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

    public AlgId algId() {
        return FoundationJNI.INSTANCE.compoundKeyAlg_algId(this.cCtx);
    }

    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.compoundKeyAlg_produceAlgInfo(this.cCtx);
    }

    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.compoundKeyAlg_restoreAlgInfo(this.cCtx, algInfo);
    }

    public PrivateKey generateEphemeralKey(Key key) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_generateEphemeralKey(this.cCtx, key);
    }

    public PublicKey importPublicKey(RawPublicKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_importPublicKey(this.cCtx, rawKey);
    }

    public RawPublicKey exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_exportPublicKey(this.cCtx, publicKey);
    }

    public PrivateKey importPrivateKey(RawPrivateKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_importPrivateKey(this.cCtx, rawKey);
    }

    public RawPrivateKey exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_exportPrivateKey(this.cCtx, privateKey);
    }

    public boolean canEncrypt(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_canEncrypt(this.cCtx, publicKey, dataLen);
    }

    public int encryptedLen(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_encryptedLen(this.cCtx, publicKey, dataLen);
    }

    public byte[] encrypt(PublicKey publicKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_encrypt(this.cCtx, publicKey, data);
    }

    public boolean canDecrypt(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_canDecrypt(this.cCtx, privateKey, dataLen);
    }

    public int decryptedLen(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_decryptedLen(this.cCtx, privateKey, dataLen);
    }

    public byte[] decrypt(PrivateKey privateKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_decrypt(this.cCtx, privateKey, data);
    }

    public boolean canSign(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_canSign(this.cCtx, privateKey);
    }

    public int signatureLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_signatureLen(this.cCtx, privateKey);
    }

    public byte[] signHash(PrivateKey privateKey, AlgId hashId, byte[] digest) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_signHash(this.cCtx, privateKey, hashId, digest);
    }

    public boolean canVerify(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_canVerify(this.cCtx, publicKey);
    }

    public boolean verifyHash(PublicKey publicKey, AlgId hashId, byte[] digest, byte[] signature) {
        return FoundationJNI.INSTANCE.compoundKeyAlg_verifyHash(this.cCtx, publicKey, hashId, digest, signature);
    }

    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.compoundKeyAlg_setupDefaults(this.cCtx);
    }

    public PrivateKey makeKey(PrivateKey cipherKey, PrivateKey signerKey) throws FoundationException {
        return FoundationJNI.INSTANCE.compoundKeyAlg_makeKey(this.cCtx, cipherKey, signerKey);
    }

}
