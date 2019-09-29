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
* Handle meta information about footer.
*/
public class FooterInfo implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public FooterInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.footerInfo_new();
    }

    /* Wrap underlying C context. */
    FooterInfo(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static FooterInfo getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new FooterInfo(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.footerInfo_close(this.cCtx);
    }

    /*
    * Retrun true if signed data info present.
    */
    public boolean hasSignedDataInfo() {
        return FoundationJNI.INSTANCE.footerInfo_hasSignedDataInfo(this.cCtx);
    }

    /*
    * Setup signed data info.
    */
    public void setSignedDataInfo(SignedDataInfo signedDataInfo) {
        FoundationJNI.INSTANCE.footerInfo_setSignedDataInfo(this.cCtx, signedDataInfo);
    }

    /*
    * Return signed data info.
    */
    public SignedDataInfo signedDataInfo() {
        return FoundationJNI.INSTANCE.footerInfo_signedDataInfo(this.cCtx);
    }

    /*
    * Remove signed data info.
    */
    public void removeSignedDataInfo() {
        FoundationJNI.INSTANCE.footerInfo_removeSignedDataInfo(this.cCtx);
    }

    /*
    * Set data size.
    */
    public void setDataSize(int dataSize) {
        FoundationJNI.INSTANCE.footerInfo_setDataSize(this.cCtx, dataSize);
    }

    /*
    * Return data size.
    */
    public int dataSize() {
        return FoundationJNI.INSTANCE.footerInfo_dataSize(this.cCtx);
    }
}

