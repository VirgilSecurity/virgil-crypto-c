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

public class MessageInfoDerSerializer implements AutoCloseable, MessageInfoSerializer, MessageInfoFooterSerializer {

    public long cCtx;

    public MessageInfoDerSerializer() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfoDerSerializer_new();
    }

    package MessageInfoDerSerializer(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public MessageInfoDerSerializer getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new MessageInfoDerSerializer(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.messageInfoDerSerializer_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setAsn1Reader(Asn1Reader asn1Reader) {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_setAsn1Reader(this.cCtx, asn1Reader);
    }

    public void setAsn1Writer(Asn1Writer asn1Writer) {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_setAsn1Writer(this.cCtx, asn1Writer);
    }

    public int getPrefixLen() {
        return 32;
    }

    public int serializedLen(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedLen(this.cCtx, messageInfo);
    }

    public byte[] serialize(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serialize(this.cCtx, messageInfo);
    }

    public int readPrefix(byte[] data) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_readPrefix(this.cCtx, data);
    }

    public MessageInfo deserialize(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_deserialize(this.cCtx, data);
    }

    public int serializedFooterLen(MessageInfoFooter messageInfoFooter) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedFooterLen(this.cCtx, messageInfoFooter);
    }

    public byte[] serializeFooter(MessageInfoFooter messageInfoFooter) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeFooter(this.cCtx, messageInfoFooter);
    }

    public MessageInfoFooter deserializeFooter(byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeFooter(this.cCtx, data);
    }

    public void setupDefaults() {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_setupDefaults(this.cCtx);
    }

    public int serializedCustomParamsLen(MessageInfoCustomParams customParams) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedCustomParamsLen(this.cCtx, customParams);
    }

    public int serializeCustomParams(MessageInfoCustomParams customParams) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeCustomParams(this.cCtx, customParams);
    }

    public int serializedFooterInfoLen(FooterInfo footerInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedFooterInfoLen(this.cCtx, footerInfo);
    }

    public int serializeFooterInfo(FooterInfo footerInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeFooterInfo(this.cCtx, footerInfo);
    }

    public int serializeSignedDataInfoInternal(SignedDataInfo signedDataInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeSignedDataInfoInternal(this.cCtx, signedDataInfo);
    }

    public int serializedKeyRecipientInfoLen(KeyRecipientInfo keyRecipientInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedKeyRecipientInfoLen(this.cCtx, keyRecipientInfo);
    }

    public int serializeKeyRecipientInfo(KeyRecipientInfo keyRecipientInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeKeyRecipientInfo(this.cCtx, keyRecipientInfo);
    }

    public int serializedPasswordRecipientInfoLen(PasswordRecipientInfo passwordRecipientInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedPasswordRecipientInfoLen(this.cCtx, passwordRecipientInfo);
    }

    public int serializePasswordRecipientInfo(PasswordRecipientInfo passwordRecipientInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializePasswordRecipientInfo(this.cCtx, passwordRecipientInfo);
    }

    public int serializedRecipientInfosLen(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedRecipientInfosLen(this.cCtx, messageInfo);
    }

    public int serializeRecipientInfos(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeRecipientInfos(this.cCtx, messageInfo);
    }

    public int serializedEncryptedContentInfoLen(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedEncryptedContentInfoLen(this.cCtx, messageInfo);
    }

    public int serializeEncryptedContentInfo(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeEncryptedContentInfo(this.cCtx, messageInfo);
    }

    public int serializedEnvelopedDataLen(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedEnvelopedDataLen(this.cCtx, messageInfo);
    }

    public int serializeEnvelopedData(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeEnvelopedData(this.cCtx, messageInfo);
    }

    public int serializedCmsContentInfoLen(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedCmsContentInfoLen(this.cCtx, messageInfo);
    }

    public int serializeCmsContentInfo(MessageInfo messageInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeCmsContentInfo(this.cCtx, messageInfo);
    }

    public int serializedSignerInfosLen(MessageInfoFooter messageInfoFooter) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedSignerInfosLen(this.cCtx, messageInfoFooter);
    }

    public int serializeSignerInfos(MessageInfoFooter messageInfoFooter) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeSignerInfos(this.cCtx, messageInfoFooter);
    }

    public int serializedSignerInfoLen(SignerInfo signerInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializedSignerInfoLen(this.cCtx, signerInfo);
    }

    public int serializeSignerInfo(SignerInfo signerInfo) {
        return FoundationJNI.INSTANCE.messageInfoDerSerializer_serializeSignerInfo(this.cCtx, signerInfo);
    }

    public void deserializeCustomParams(MessageInfoCustomParams customParams) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeCustomParams(this.cCtx, customParams);
    }

    public void deserializeCipherKdf(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeCipherKdf(this.cCtx, messageInfo);
    }

    public void deserializeCipherPadding(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeCipherPadding(this.cCtx, messageInfo);
    }

    public void deserializeFooterInfo(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeFooterInfo(this.cCtx, messageInfo);
    }

    public void deserializeSignedDataInfo(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeSignedDataInfo(this.cCtx, messageInfo);
    }

    public void deserializeKeyRecipientInfo(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeKeyRecipientInfo(this.cCtx, messageInfo);
    }

    public void deserializePasswordRecipientInfo(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializePasswordRecipientInfo(this.cCtx, messageInfo);
    }

    public void deserializeRecipientInfos(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeRecipientInfos(this.cCtx, messageInfo);
    }

    public void deserializeEncryptedContentInfo(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeEncryptedContentInfo(this.cCtx, messageInfo);
    }

    public void deserializeEnvelopedData(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeEnvelopedData(this.cCtx, messageInfo);
    }

    public void deserializeCmsContentInfo(MessageInfo messageInfo) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeCmsContentInfo(this.cCtx, messageInfo);
    }

    public void deserializeSignerInfos(MessageInfoFooter messageInfoFooter) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeSignerInfos(this.cCtx, messageInfoFooter);
    }

    public void deserializeSignerInfo(MessageInfoFooter messageInfoFooter) throws FoundationException {
        FoundationJNI.INSTANCE.messageInfoDerSerializer_deserializeSignerInfo(this.cCtx, messageInfoFooter);
    }

}
