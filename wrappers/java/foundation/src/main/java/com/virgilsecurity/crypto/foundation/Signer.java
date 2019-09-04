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
* Sign data of any size.
*/
public class Signer implements AutoCloseable {

    public java.nio.ByteBuffer cCtx;

    /* Create underlying C context. */
    public Signer() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.signer_new();
    }

    /* Wrap underlying C context. */
    Signer(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Signer getInstance(java.nio.ByteBuffer cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Signer(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.signer_close(this.cCtx);
    }

    public void setHash(Hash hash) {
        FoundationJNI.INSTANCE.signer_setHash(this.cCtx, hash);
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.signer_setRandom(this.cCtx, random);
    }

    /*
    * Start a processing a new signature.
    */
    public void reset() {
        FoundationJNI.INSTANCE.signer_reset(this.cCtx);
    }

    /*
    * Add given data to the signed data.
    */
    public void appendData(byte[] data) {
        FoundationJNI.INSTANCE.signer_appendData(this.cCtx, data);
    }

    /*
    * Return length of the signature.
    */
    public int signatureLen(PrivateKey privateKey) {
        return FoundationJNI.INSTANCE.signer_signatureLen(this.cCtx, privateKey);
    }

    /*
    * Accomplish signing and return signature.
    */
    public byte[] sign(PrivateKey privateKey) throws FoundationException {
        return FoundationJNI.INSTANCE.signer_sign(this.cCtx, privateKey);
    }
}

