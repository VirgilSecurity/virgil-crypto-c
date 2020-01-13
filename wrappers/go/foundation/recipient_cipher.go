package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This class provides hybrid encryption algorithm that combines symmetric
* cipher for data encryption and asymmetric cipher and password based
* cipher for symmetric key encryption.
*/
type RecipientCipher struct {
    cCtx *C.vscf_recipient_cipher_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RecipientCipher) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRecipientCipher() *RecipientCipher {
    ctx := C.vscf_recipient_cipher_new()
    obj := &RecipientCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RecipientCipher).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRecipientCipherWithCtx(ctx *C.vscf_recipient_cipher_t /*ct2*/) *RecipientCipher {
    obj := &RecipientCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RecipientCipher).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRecipientCipherCopy(ctx *C.vscf_recipient_cipher_t /*ct2*/) *RecipientCipher {
    obj := &RecipientCipher {
        cCtx: C.vscf_recipient_cipher_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RecipientCipher).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RecipientCipher) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RecipientCipher) delete() {
    C.vscf_recipient_cipher_delete(obj.cCtx)
}

func (obj *RecipientCipher) SetRandom(random Random) {
    C.vscf_recipient_cipher_release_random(obj.cCtx)
    C.vscf_recipient_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *RecipientCipher) SetEncryptionCipher(encryptionCipher Cipher) {
    C.vscf_recipient_cipher_release_encryption_cipher(obj.cCtx)
    C.vscf_recipient_cipher_use_encryption_cipher(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(encryptionCipher.Ctx())))

    runtime.KeepAlive(encryptionCipher)
    runtime.KeepAlive(obj)
}

func (obj *RecipientCipher) SetEncryptionPadding(encryptionPadding Padding) {
    C.vscf_recipient_cipher_release_encryption_padding(obj.cCtx)
    C.vscf_recipient_cipher_use_encryption_padding(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(encryptionPadding.Ctx())))

    runtime.KeepAlive(encryptionPadding)
    runtime.KeepAlive(obj)
}

func (obj *RecipientCipher) SetPaddingParams(paddingParams *PaddingParams) {
    C.vscf_recipient_cipher_release_padding_params(obj.cCtx)
    C.vscf_recipient_cipher_use_padding_params(obj.cCtx, (*C.vscf_padding_params_t)(unsafe.Pointer(paddingParams.Ctx())))

    runtime.KeepAlive(paddingParams)
    runtime.KeepAlive(obj)
}

func (obj *RecipientCipher) SetSignerHash(signerHash Hash) {
    C.vscf_recipient_cipher_release_signer_hash(obj.cCtx)
    C.vscf_recipient_cipher_use_signer_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(signerHash.Ctx())))

    runtime.KeepAlive(signerHash)
    runtime.KeepAlive(obj)
}

/*
* Return true if a key recipient with a given id has been added.
* Note, operation has O(N) time complexity.
*/
func (obj *RecipientCipher) HasKeyRecipient(recipientId []byte) bool {
    recipientIdData := helperWrapData (recipientId)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_has_key_recipient(obj.cCtx, recipientIdData)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Add recipient defined with id and public key.
*/
func (obj *RecipientCipher) AddKeyRecipient(recipientId []byte, publicKey PublicKey) {
    recipientIdData := helperWrapData (recipientId)

    C.vscf_recipient_cipher_add_key_recipient(obj.cCtx, recipientIdData, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return
}

/*
* Remove all recipients.
*/
func (obj *RecipientCipher) ClearRecipients() {
    C.vscf_recipient_cipher_clear_recipients(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Add identifier and private key to sign initial plain text.
* Return error if the private key can not sign.
*/
func (obj *RecipientCipher) AddSigner(signerId []byte, privateKey PrivateKey) error {
    signerIdData := helperWrapData (signerId)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_add_signer(obj.cCtx, signerIdData, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return nil
}

/*
* Remove all signers.
*/
func (obj *RecipientCipher) ClearSigners() {
    C.vscf_recipient_cipher_clear_signers(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Provide access to the custom params object.
* The returned object can be used to add custom params or read it.
*/
func (obj *RecipientCipher) CustomParams() *MessageInfoCustomParams {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_custom_params(obj.cCtx)

    runtime.KeepAlive(obj)

    return newMessageInfoCustomParamsCopy(proxyResult) /* r5 */
}

/*
* Start encryption process.
*/
func (obj *RecipientCipher) StartEncryption() error {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_encryption(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Start encryption process with known plain text size.
*
* Precondition: At least one signer should be added.
* Note, store message info footer as well.
*/
func (obj *RecipientCipher) StartSignedEncryption(dataSize uint) error {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_signed_encryption(obj.cCtx, (C.size_t)(dataSize)/*pa10*/)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Return buffer length required to hold message info returned by the
* "pack message info" method.
* Precondition: all recipients and custom parameters should be set.
*/
func (obj *RecipientCipher) MessageInfoLen() uint {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_message_info_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
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
func (obj *RecipientCipher) PackMessageInfo() []byte {
    messageInfoBuf, messageInfoBufErr := newBuffer(int(obj.MessageInfoLen() /* lg2 */))
    if messageInfoBufErr != nil {
        return nil
    }
    defer messageInfoBuf.delete()


    C.vscf_recipient_cipher_pack_message_info(obj.cCtx, messageInfoBuf.ctx)

    runtime.KeepAlive(obj)

    return messageInfoBuf.getData() /* r7 */
}

/*
* Return buffer length required to hold output of the method
* "process encryption" and method "finish" during encryption.
*/
func (obj *RecipientCipher) EncryptionOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_encryption_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Process encryption of a new portion of data.
*/
func (obj *RecipientCipher) ProcessEncryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptionOutLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_process_encryption(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Accomplish encryption.
*/
func (obj *RecipientCipher) FinishEncryption() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptionOutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_recipient_cipher_finish_encryption(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Initiate decryption process with a recipient private key.
* Message Info can be empty if it was embedded to encrypted data.
*/
func (obj *RecipientCipher) StartDecryptionWithKey(recipientId []byte, privateKey PrivateKey, messageInfo []byte) error {
    recipientIdData := helperWrapData (recipientId)
    messageInfoData := helperWrapData (messageInfo)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_decryption_with_key(obj.cCtx, recipientIdData, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), messageInfoData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return nil
}

/*
* Initiate decryption process with a recipient private key.
* Message Info can be empty if it was embedded to encrypted data.
* Message Info footer can be empty if it was embedded to encrypted data.
* If footer was embedded, method "start decryption with key" can be used.
*/
func (obj *RecipientCipher) StartVerifiedDecryptionWithKey(recipientId []byte, privateKey PrivateKey, messageInfo []byte, messageInfoFooter []byte) error {
    recipientIdData := helperWrapData (recipientId)
    messageInfoData := helperWrapData (messageInfo)
    messageInfoFooterData := helperWrapData (messageInfoFooter)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_verified_decryption_with_key(obj.cCtx, recipientIdData, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), messageInfoData, messageInfoFooterData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return nil
}

/*
* Return buffer length required to hold output of the method
* "process decryption" and method "finish" during decryption.
*/
func (obj *RecipientCipher) DecryptionOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_decryption_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Process with a new portion of data.
* Return error if data can not be encrypted or decrypted.
*/
func (obj *RecipientCipher) ProcessDecryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptionOutLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_process_decryption(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Accomplish decryption.
*/
func (obj *RecipientCipher) FinishDecryption() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptionOutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_recipient_cipher_finish_decryption(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Return true if data was signed by a sender.
*
* Precondition: this method should be called after "finish decryption".
*/
func (obj *RecipientCipher) IsDataSigned() bool {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_is_data_signed(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return information about signers that sign data.
*
* Precondition: this method should be called after "finish decryption".
* Precondition: method "is data signed" returns true.
*/
func (obj *RecipientCipher) SignerInfos() *SignerInfoList {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_signer_infos(obj.cCtx)

    runtime.KeepAlive(obj)

    return newSignerInfoListCopy(proxyResult) /* r5 */
}

/*
* Verify given cipher info.
*/
func (obj *RecipientCipher) VerifySignerInfo(signerInfo *SignerInfo, publicKey PublicKey) bool {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_verify_signer_info(obj.cCtx, (*C.vscf_signer_info_t)(unsafe.Pointer(signerInfo.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(signerInfo)

    runtime.KeepAlive(publicKey)

    return bool(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold message footer returned by the
* "pack message footer" method.
*
* Precondition: this method should be called after "finish encryption".
*/
func (obj *RecipientCipher) MessageInfoFooterLen() uint {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_message_info_footer_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
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
func (obj *RecipientCipher) PackMessageInfoFooter() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.MessageInfoFooterLen() /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_recipient_cipher_pack_message_info_footer(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}
