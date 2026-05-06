/**
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


const precondition = require('./precondition');

const initMessageInfoDerSerializer = (Module, modules) => {
    class MessageInfoDerSerializer {

        constructor(ctxPtr) {
            this.name = 'MessageInfoDerSerializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_message_info_der_serializer_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfoDerSerializer(Module._vscf_message_info_der_serializer_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfoDerSerializer(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_message_info_der_serializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set asn1Reader(asn1Reader) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('asn1Reader', asn1Reader, 'Foundation.Asn1Reader', modules.FoundationInterfaceTag.ASN1_READER, modules.FoundationInterface);
            Module._vscf_message_info_der_serializer_release_asn1_reader(this.ctxPtr)
            Module._vscf_message_info_der_serializer_use_asn1_reader(this.ctxPtr, asn1Reader.ctxPtr)
        }

        set asn1Writer(asn1Writer) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('asn1Writer', asn1Writer, 'Foundation.Asn1Writer', modules.FoundationInterfaceTag.ASN1_WRITER, modules.FoundationInterface);
            Module._vscf_message_info_der_serializer_release_asn1_writer(this.ctxPtr)
            Module._vscf_message_info_der_serializer_use_asn1_writer(this.ctxPtr, asn1Writer.ctxPtr)
        }

        static get PREFIX_LEN() {
            return 32;
        }

        get PREFIX_LEN() {
            return 32;
        }

        serializedLen(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_len(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serialize(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const outCapacity = this.serializedLen(messageInfo);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                Module._vscf_message_info_der_serializer_serialize(this.ctxPtr, messageInfo.ctxPtr, outCtxPtr);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        readPrefix(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);
            
            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);
            
            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_read_prefix(this.ctxPtr, dataCtxPtr);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        deserialize(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);
            
            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);
            
            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize(this.ctxPtr, dataCtxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.MessageInfo.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        serializedFooterLen(messageInfoFooter) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfoFooter', messageInfoFooter, modules.MessageInfoFooter);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_footer_len(this.ctxPtr, messageInfoFooter.ctxPtr);
            return proxyResult;
        }

        serializeFooter(messageInfoFooter) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfoFooter', messageInfoFooter, modules.MessageInfoFooter);
            
            const outCapacity = this.serializedFooterLen(messageInfoFooter);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                Module._vscf_message_info_der_serializer_serialize_footer(this.ctxPtr, messageInfoFooter.ctxPtr, outCtxPtr);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        deserializeFooter(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);
            
            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);
            
            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_footer(this.ctxPtr, dataCtxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.MessageInfoFooter.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_message_info_der_serializer_setup_defaults(this.ctxPtr);
        }

        serializedCustomParamsLen(customParams) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('customParams', customParams, modules.MessageInfoCustomParams);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_custom_params_len(this.ctxPtr, customParams.ctxPtr);
            return proxyResult;
        }

        serializeCustomParams(customParams) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('customParams', customParams, modules.MessageInfoCustomParams);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_custom_params(this.ctxPtr, customParams.ctxPtr);
            return proxyResult;
        }

        serializedFooterInfoLen(footerInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('footerInfo', footerInfo, modules.FooterInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_footer_info_len(this.ctxPtr, footerInfo.ctxPtr);
            return proxyResult;
        }

        serializeFooterInfo(footerInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('footerInfo', footerInfo, modules.FooterInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_footer_info(this.ctxPtr, footerInfo.ctxPtr);
            return proxyResult;
        }

        serializeSignedDataInfoInternal(signedDataInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('signedDataInfo', signedDataInfo, modules.SignedDataInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_signed_data_info_internal(this.ctxPtr, signedDataInfo.ctxPtr);
            return proxyResult;
        }

        serializedKeyRecipientInfoLen(keyRecipientInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('keyRecipientInfo', keyRecipientInfo, modules.KeyRecipientInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_key_recipient_info_len(this.ctxPtr, keyRecipientInfo.ctxPtr);
            return proxyResult;
        }

        serializeKeyRecipientInfo(keyRecipientInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('keyRecipientInfo', keyRecipientInfo, modules.KeyRecipientInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_key_recipient_info(this.ctxPtr, keyRecipientInfo.ctxPtr);
            return proxyResult;
        }

        serializedPasswordRecipientInfoLen(passwordRecipientInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('passwordRecipientInfo', passwordRecipientInfo, modules.PasswordRecipientInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_password_recipient_info_len(this.ctxPtr, passwordRecipientInfo.ctxPtr);
            return proxyResult;
        }

        serializePasswordRecipientInfo(passwordRecipientInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('passwordRecipientInfo', passwordRecipientInfo, modules.PasswordRecipientInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_password_recipient_info(this.ctxPtr, passwordRecipientInfo.ctxPtr);
            return proxyResult;
        }

        serializedRecipientInfosLen(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_recipient_infos_len(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializeRecipientInfos(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_recipient_infos(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializedEncryptedContentInfoLen(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_encrypted_content_info_len(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializeEncryptedContentInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_encrypted_content_info(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializedEnvelopedDataLen(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_enveloped_data_len(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializeEnvelopedData(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_enveloped_data(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializedCmsContentInfoLen(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_cms_content_info_len(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializeCmsContentInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_cms_content_info_(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        serializedSignerInfosLen(messageInfoFooter) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfoFooter', messageInfoFooter, modules.MessageInfoFooter);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_signer_infos_len(this.ctxPtr, messageInfoFooter.ctxPtr);
            return proxyResult;
        }

        serializeSignerInfos(messageInfoFooter) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfoFooter', messageInfoFooter, modules.MessageInfoFooter);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_signer_infos(this.ctxPtr, messageInfoFooter.ctxPtr);
            return proxyResult;
        }

        serializedSignerInfoLen(signerInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('signerInfo', signerInfo, modules.SignerInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_signer_info_len(this.ctxPtr, signerInfo.ctxPtr);
            return proxyResult;
        }

        serializeSignerInfo(signerInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('signerInfo', signerInfo, modules.SignerInfo);
            
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialize_signer_info(this.ctxPtr, signerInfo.ctxPtr);
            return proxyResult;
        }

        deserializeCustomParams(customParams) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('customParams', customParams, modules.MessageInfoCustomParams);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_custom_params(this.ctxPtr, customParams.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeCipherKdf(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_cipher_kdf(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeCipherPadding(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_cipher_padding(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeFooterInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_footer_info(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeSignedDataInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_signed_data_info(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeKeyRecipientInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_key_recipient_info(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializePasswordRecipientInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_password_recipient_info(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeRecipientInfos(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_recipient_infos(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeEncryptedContentInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_encrypted_content_info(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeEnvelopedData(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_enveloped_data(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeCmsContentInfo(messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfo', messageInfo, modules.MessageInfo);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_cms_content_info(this.ctxPtr, messageInfo.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeSignerInfos(messageInfoFooter) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfoFooter', messageInfoFooter, modules.MessageInfoFooter);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_signer_infos(this.ctxPtr, messageInfoFooter.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeSignerInfo(messageInfoFooter) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('messageInfoFooter', messageInfoFooter, modules.MessageInfoFooter);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize_signer_info(this.ctxPtr, messageInfoFooter.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(errorCtxPtr);
            }
        }

    }

    return MessageInfoDerSerializer;
};

module.exports = initMessageInfoDerSerializer;
