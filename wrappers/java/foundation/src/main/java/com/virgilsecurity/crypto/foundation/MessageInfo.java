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

public class MessageInfo implements AutoCloseable {

    public long cCtx;

    public MessageInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfo_new();
    }

    MessageInfo(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static MessageInfo getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfo(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.messageInfo_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public AlgInfo dataEncryptionAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_dataEncryptionAlgInfo(this.cCtx);
    }

    public KeyRecipientInfoList keyRecipientInfoList() {
        return FoundationJNI.INSTANCE.messageInfo_keyRecipientInfoList(this.cCtx);
    }

    public PasswordRecipientInfoList passwordRecipientInfoList() {
        return FoundationJNI.INSTANCE.messageInfo_passwordRecipientInfoList(this.cCtx);
    }

    public KekRecipientInfoList kekRecipientInfoList() {
        return FoundationJNI.INSTANCE.messageInfo_kekRecipientInfoList(this.cCtx);
    }

    public boolean hasCustomParams() {
        return FoundationJNI.INSTANCE.messageInfo_hasCustomParams(this.cCtx);
    }

    public MessageInfoCustomParams customParams() {
        return FoundationJNI.INSTANCE.messageInfo_customParams(this.cCtx);
    }

    public boolean hasCipherKdfAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_hasCipherKdfAlgInfo(this.cCtx);
    }

    public AlgInfo cipherKdfAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_cipherKdfAlgInfo(this.cCtx);
    }

    public boolean hasCipherPaddingAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_hasCipherPaddingAlgInfo(this.cCtx);
    }

    public AlgInfo cipherPaddingAlgInfo() {
        return FoundationJNI.INSTANCE.messageInfo_cipherPaddingAlgInfo(this.cCtx);
    }

    public boolean hasFooterInfo() {
        return FoundationJNI.INSTANCE.messageInfo_hasFooterInfo(this.cCtx);
    }

    public FooterInfo footerInfo() {
        return FoundationJNI.INSTANCE.messageInfo_footerInfo(this.cCtx);
    }

    public void clear() {
        FoundationJNI.INSTANCE.messageInfo_clear(this.cCtx);
    }

}
