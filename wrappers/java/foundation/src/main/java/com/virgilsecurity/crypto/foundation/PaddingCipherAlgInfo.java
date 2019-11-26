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
* Handle algorithm information about padding cipher.
*/
public class PaddingCipherAlgInfo implements AutoCloseable, AlgInfo {

    public long cCtx;

    /* Create underlying C context. */
    public PaddingCipherAlgInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.paddingCipherAlgInfo_new();
    }

    /* Wrap underlying C context. */
    PaddingCipherAlgInfo(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Create algorithm an underlying cipher alg info and a padding frame.
    */
    public PaddingCipherAlgInfo(AlgInfo underlyingCipher, int paddingFrame) {
        super();
        this.cCtx = FoundationJNI.INSTANCE.paddingCipherAlgInfo_new(underlyingCipher, paddingFrame);
    }

    /*
    * Return underlying cipher alg info.
    */
    public AlgInfo underlyingCipher() {
        return FoundationJNI.INSTANCE.paddingCipherAlgInfo_underlyingCipher(this.cCtx);
    }

    /*
    * Return padding frame.
    */
    public int paddingFrame() {
        return FoundationJNI.INSTANCE.paddingCipherAlgInfo_paddingFrame(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static PaddingCipherAlgInfo getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new PaddingCipherAlgInfo(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.paddingCipherAlgInfo_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.paddingCipherAlgInfo_algId(this.cCtx);
    }
}

