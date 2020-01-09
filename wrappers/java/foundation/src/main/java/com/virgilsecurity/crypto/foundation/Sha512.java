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
* This is MbedTLS implementation of SHA512.
*/
public class Sha512 implements AutoCloseable, Alg, Hash {

    public long cCtx;

    /* Create underlying C context. */
    public Sha512() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.sha512_new();
    }

    /* Wrap underlying C context. */
    Sha512(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Sha512 getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Sha512(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.sha512_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.sha512_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.sha512_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.sha512_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Length of the digest (hashing output) in bytes.
    */
    public int getDigestLen() {
        return 64;
    }

    /*
    * Block length of the digest function in bytes.
    */
    public int getBlockLen() {
        return 128;
    }

    /*
    * Calculate hash over given data.
    */
    public byte[] hash(byte[] data) {
        return FoundationJNI.INSTANCE.sha512_hash(data);
    }

    /*
    * Start a new hashing.
    */
    public void start() {
        FoundationJNI.INSTANCE.sha512_start(this.cCtx);
    }

    /*
    * Add given data to the hash.
    */
    public void update(byte[] data) {
        FoundationJNI.INSTANCE.sha512_update(this.cCtx, data);
    }

    /*
    * Accompilsh hashing and return it's result (a message digest).
    */
    public byte[] finish() {
        return FoundationJNI.INSTANCE.sha512_finish(this.cCtx);
    }
}

