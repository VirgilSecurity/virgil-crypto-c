package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* This class provides hybrid encryption algorithm that combines symmetric
* cipher for data encryption and asymmetric cipher and password based
* cipher for symmetric key encryption.
*/
type RecipientCipher struct {
    cCtx *C.vscf_recipient_cipher_t /*ct2*/
}

/* Handle underlying C context. */
func (this RecipientCipher) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewRecipientCipher () *RecipientCipher {
    ctx := C.vscf_recipient_cipher_new()
    return &RecipientCipher {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRecipientCipherWithCtx (ctx *C.vscf_recipient_cipher_t /*ct2*/) *RecipientCipher {
    return &RecipientCipher {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRecipientCipherCopy (ctx *C.vscf_recipient_cipher_t /*ct2*/) *RecipientCipher {
    return &RecipientCipher {
        cCtx: C.vscf_recipient_cipher_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this RecipientCipher) close () {
    C.vscf_recipient_cipher_delete(this.cCtx)
}

func (this RecipientCipher) SetRandom (random IRandom) {
    C.vscf_recipient_cipher_release_random(this.cCtx)
    C.vscf_recipient_cipher_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (this RecipientCipher) SetEncryptionCipher (encryptionCipher ICipher) {
    C.vscf_recipient_cipher_release_encryption_cipher(this.cCtx)
    C.vscf_recipient_cipher_use_encryption_cipher(this.cCtx, (*C.vscf_impl_t)(encryptionCipher.ctx()))
}

func (this RecipientCipher) SetSignerHash (signerHash IHash) {
    C.vscf_recipient_cipher_release_signer_hash(this.cCtx)
    C.vscf_recipient_cipher_use_signer_hash(this.cCtx, (*C.vscf_impl_t)(signerHash.ctx()))
}

/*
* Return true if a key recipient with a given id has been added.
* Note, operation has O(N) time complexity.
*/
func (this RecipientCipher) HasKeyRecipient (recipientId []byte) bool {
    recipientIdData := C.vsc_data((*C.uint8_t)(&recipientId[0]), C.size_t(len(recipientId)))

    proxyResult := /*pr4*/C.vscf_recipient_cipher_has_key_recipient(this.cCtx, recipientIdData)

    return bool(proxyResult) /* r9 */
}

/*
* Add recipient defined with id and public key.
*/
func (this RecipientCipher) AddKeyRecipient (recipientId []byte, publicKey IPublicKey) {
    recipientIdData := C.vsc_data((*C.uint8_t)(&recipientId[0]), C.size_t(len(recipientId)))

    C.vscf_recipient_cipher_add_key_recipient(this.cCtx, recipientIdData, (*C.vscf_impl_t)(publicKey.ctx()))

    return
}

/*
* Remove all recipients.
*/
func (this RecipientCipher) ClearRecipients () {
    C.vscf_recipient_cipher_clear_recipients(this.cCtx)

    return
}

/*
* Add identifier and private key to sign initial plain text.
* Return error if the private key can not sign.
*/
func (this RecipientCipher) AddSigner (signerId []byte, privateKey IPrivateKey) error {
    signerIdData := C.vsc_data((*C.uint8_t)(&signerId[0]), C.size_t(len(signerId)))

    proxyResult := /*pr4*/C.vscf_recipient_cipher_add_signer(this.cCtx, signerIdData, (*C.vscf_impl_t)(privateKey.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Remove all signers.
*/
func (this RecipientCipher) ClearSigners () {
    C.vscf_recipient_cipher_clear_signers(this.cCtx)

    return
}

/*
* Provide access to the custom params object.
* The returned object can be used to add custom params or read it.
*/
func (this RecipientCipher) CustomParams () *MessageInfoCustomParams {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_custom_params(this.cCtx)

    return newMessageInfoCustomParamsWithCtx(proxyResult) /* r5 */
}

/*
* Start encryption process.
*/
func (this RecipientCipher) StartEncryption () error {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_encryption(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Start encryption process with known plain text size.
*
* Precondition: At least one signer should be added.
* Note, store message info footer as well.
*/
func (this RecipientCipher) StartSignedEncryption (dataSize uint32) error {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_signed_encryption(this.cCtx, (C.size_t)(dataSize)/*pa10*/)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Return buffer length required to hold message info returned by the
* "pack message info" method.
* Precondition: all recipients and custom parameters should be set.
*/
func (this RecipientCipher) MessageInfoLen () uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_message_info_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Return serialized message info to the buffer.
*
* Precondition: this method should be called after "start encryption".
* Precondition: this method should be called before "finish encryption".
*
* Note, store message info to use it for decryption process,
* or place it at the encrypted data beginning (embedding).
*
* Return message info - recipients public information,
* algorithm information, etc.
*/
func (this RecipientCipher) PackMessageInfo () []byte {
    messageInfoCount := C.ulong(this.MessageInfoLen() /* lg2 */)
    messageInfoMemory := make([]byte, int(C.vsc_buffer_ctx_size() + messageInfoCount))
    messageInfoBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&messageInfoMemory[0]))
    messageInfoData := messageInfoMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(messageInfoBuf)
    C.vsc_buffer_use(messageInfoBuf, (*C.byte)(unsafe.Pointer(&messageInfoData[0])), messageInfoCount)
    defer C.vsc_buffer_delete(messageInfoBuf)


    C.vscf_recipient_cipher_pack_message_info(this.cCtx, messageInfoBuf)

    return messageInfoData[0:C.vsc_buffer_len(messageInfoBuf)] /* r7 */
}

/*
* Return buffer length required to hold output of the method
* "process encryption" and method "finish" during encryption.
*/
func (this RecipientCipher) EncryptionOutLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_encryption_out_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Process encryption of a new portion of data.
*/
func (this RecipientCipher) ProcessEncryption (data []byte) ([]byte, error) {
    outCount := C.ulong(this.EncryptionOutLen(uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_recipient_cipher_process_encryption(this.cCtx, dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Accomplish encryption.
*/
func (this RecipientCipher) FinishEncryption () ([]byte, error) {
    outCount := C.ulong(this.EncryptionOutLen(0) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_recipient_cipher_finish_encryption(this.cCtx, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Initiate decryption process with a recipient private key.
* Message Info can be empty if it was embedded to encrypted data.
*/
func (this RecipientCipher) StartDecryptionWithKey (recipientId []byte, privateKey IPrivateKey, messageInfo []byte) error {
    recipientIdData := C.vsc_data((*C.uint8_t)(&recipientId[0]), C.size_t(len(recipientId)))
    messageInfoData := C.vsc_data((*C.uint8_t)(&messageInfo[0]), C.size_t(len(messageInfo)))

    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_decryption_with_key(this.cCtx, recipientIdData, (*C.vscf_impl_t)(privateKey.ctx()), messageInfoData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Initiate decryption process with a recipient private key.
* Message Info can be empty if it was embedded to encrypted data.
* Message Info footer can be empty if it was embedded to encrypted data.
* If footer was embedded, method "start decryption with key" can be used.
*/
func (this RecipientCipher) StartVerifiedDecryptionWithKey (recipientId []byte, privateKey IPrivateKey, messageInfo []byte, messageInfoFooter []byte) error {
    recipientIdData := C.vsc_data((*C.uint8_t)(&recipientId[0]), C.size_t(len(recipientId)))
    messageInfoData := C.vsc_data((*C.uint8_t)(&messageInfo[0]), C.size_t(len(messageInfo)))
    messageInfoFooterData := C.vsc_data((*C.uint8_t)(&messageInfoFooter[0]), C.size_t(len(messageInfoFooter)))

    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_verified_decryption_with_key(this.cCtx, recipientIdData, (*C.vscf_impl_t)(privateKey.ctx()), messageInfoData, messageInfoFooterData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Return buffer length required to hold output of the method
* "process decryption" and method "finish" during decryption.
*/
func (this RecipientCipher) DecryptionOutLen (dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_decryption_out_len(this.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Process with a new portion of data.
* Return error if data can not be encrypted or decrypted.
*/
func (this RecipientCipher) ProcessDecryption (data []byte) ([]byte, error) {
    outCount := C.ulong(this.DecryptionOutLen(uint32(len(data))) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_recipient_cipher_process_decryption(this.cCtx, dataData, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Accomplish decryption.
*/
func (this RecipientCipher) FinishDecryption () ([]byte, error) {
    outCount := C.ulong(this.DecryptionOutLen(0) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_recipient_cipher_finish_decryption(this.cCtx, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Return true if data was signed by a sender.
*
* Precondition: this method should be called after "finish decryption".
*/
func (this RecipientCipher) IsDataSigned () bool {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_is_data_signed(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return information about signers that sign data.
*
* Precondition: this method should be called after "finish decryption".
* Precondition: method "is data signed" returns true.
*/
func (this RecipientCipher) SignerInfos () *SignerInfoList {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_signer_infos(this.cCtx)

    return newSignerInfoListWithCtx(proxyResult) /* r5 */
}

/*
* Verify given cipher info.
*/
func (this RecipientCipher) VerifySignerInfo (signerInfo *SignerInfo, publicKey IPublicKey) bool {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_verify_signer_info(this.cCtx, (*C.vscf_signer_info_t)(signerInfo.ctx()), (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold message footer returned by the
* "pack message footer" method.
*
* Precondition: this method should be called after "finish encryption".
*/
func (this RecipientCipher) MessageInfoFooterLen () uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_message_info_footer_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Return serialized message info footer to the buffer.
*
* Precondition: this method should be called after "finish encryption".
*
* Note, store message info to use it for verified decryption process,
* or place it at the encrypted data ending (embedding).
*
* Return message info footer - signers public information, etc.
*/
func (this RecipientCipher) PackMessageInfoFooter () ([]byte, error) {
    outCount := C.ulong(this.MessageInfoFooterLen() /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_recipient_cipher_pack_message_info_footer(this.cCtx, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
