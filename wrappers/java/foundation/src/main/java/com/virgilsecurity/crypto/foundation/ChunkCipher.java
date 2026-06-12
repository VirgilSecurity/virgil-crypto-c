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

public class ChunkCipher implements AutoCloseable {

    public long cCtx;

    public ChunkCipher() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.chunkCipher_new();
    }

    ChunkCipher(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static ChunkCipher getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new ChunkCipher(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.chunkCipher_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.chunkCipher_setRandom(this.cCtx, random);
    }

    public void setKey(byte[] key) {
        FoundationJNI.INSTANCE.chunkCipher_setKey(this.cCtx, key);
    }

    public void setNonce(byte[] nonce) {
        FoundationJNI.INSTANCE.chunkCipher_setNonce(this.cCtx, nonce);
    }

    public void setChunkSize(int chunkSize) {
        FoundationJNI.INSTANCE.chunkCipher_setChunkSize(this.cCtx, chunkSize);
    }

    public byte[] nonce() {
        return FoundationJNI.INSTANCE.chunkCipher_nonce(this.cCtx);
    }

    public int nonceLen() {
        return FoundationJNI.INSTANCE.chunkCipher_nonceLen(this.cCtx);
    }

    public int encryptionOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.chunkCipher_encryptionOutLen(this.cCtx, dataLen);
    }

    public void startEncryption() throws FoundationException {
        FoundationJNI.INSTANCE.chunkCipher_startEncryption(this.cCtx);
    }

    public byte[] processEncryption(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.chunkCipher_processEncryption(this.cCtx, data);
    }

    public byte[] finishEncryption() throws FoundationException {
        return FoundationJNI.INSTANCE.chunkCipher_finishEncryption(this.cCtx);
    }

    public int decryptionOutLen(int dataLen) {
        return FoundationJNI.INSTANCE.chunkCipher_decryptionOutLen(this.cCtx, dataLen);
    }

    public void startDecryption() throws FoundationException {
        FoundationJNI.INSTANCE.chunkCipher_startDecryption(this.cCtx);
    }

    public byte[] processDecryption(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.chunkCipher_processDecryption(this.cCtx, data);
    }

    public byte[] finishDecryption() throws FoundationException {
        return FoundationJNI.INSTANCE.chunkCipher_finishDecryption(this.cCtx);
    }

}
