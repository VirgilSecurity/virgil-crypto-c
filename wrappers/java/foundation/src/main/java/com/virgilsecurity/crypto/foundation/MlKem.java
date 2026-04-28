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

public class MlKem implements AutoCloseable, Alg, KeyAlg, Kem {

    public long cCtx;

    public MlKem() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.mlKem_new();
    }

    MlKem(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static MlKem getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MlKem(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.mlKem_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.mlKem_setRandom(this.cCtx, random);
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
        return FoundationJNI.INSTANCE.mlKem_algId(this.cCtx);
    }

    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.mlKem_produceAlgInfo(this.cCtx);
    }

    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.mlKem_restoreAlgInfo(this.cCtx, algInfo);
    }

    public PrivateKey generateEphemeralKey(Key key) throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_generateEphemeralKey(this.cCtx, key);
    }

    public PublicKey importPublicKey(RawPublicKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_importPublicKey(this.cCtx, rawKey);
    }

    public RawPublicKey exportPublicKey(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_exportPublicKey(this.cCtx, publicKey);
    }

    public PrivateKey importPrivateKey(RawPrivateKey rawKey) throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_importPrivateKey(this.cCtx, rawKey);
    }

    public RawPrivateKey exportPrivateKey(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_exportPrivateKey(this.cCtx, privateKey);
    }

    public int kemSharedKeyLen(Key key) {
        return FoundationJNI.INSTANCE.mlKem_kemSharedKeyLen(this.cCtx, key);
    }

    public int kemEncapsulatedKeyLen(PublicKey publicKey) {
        return FoundationJNI.INSTANCE.mlKem_kemEncapsulatedKeyLen(this.cCtx, publicKey);
    }

    public KemKemEncapsulateResult kemEncapsulate(PublicKey publicKey) throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_kemEncapsulate(this.cCtx, publicKey);
    }

    public byte[] kemDecapsulate(byte[] encapsulatedKey, PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_kemDecapsulate(this.cCtx, encapsulatedKey, privateKey);
    }

    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.mlKem_setupDefaults(this.cCtx);
    }

    public PrivateKey generateKey() throws FoundationException {
        return FoundationJNI.INSTANCE.mlKem_generateKey(this.cCtx);
    }

}
