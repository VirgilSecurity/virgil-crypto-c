package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
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
func (obj *RecipientCipher) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRecipientCipher() *RecipientCipher {
    ctx := C.vscf_recipient_cipher_new()
    obj := &RecipientCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRecipientCipherWithCtx(ctx *C.vscf_recipient_cipher_t /*ct2*/) *RecipientCipher {
    obj := &RecipientCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRecipientCipherCopy(ctx *C.vscf_recipient_cipher_t /*ct2*/) *RecipientCipher {
    obj := &RecipientCipher {
        cCtx: C.vscf_recipient_cipher_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RecipientCipher) Delete() {
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
    C.vscf_recipient_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (obj *RecipientCipher) SetEncryptionCipher(encryptionCipher Cipher) {
    C.vscf_recipient_cipher_release_encryption_cipher(obj.cCtx)
    C.vscf_recipient_cipher_use_encryption_cipher(obj.cCtx, (*C.vscf_impl_t)(encryptionCipher.ctx()))
}

func (obj *RecipientCipher) SetSignerHash(signerHash Hash) {
    C.vscf_recipient_cipher_release_signer_hash(obj.cCtx)
    C.vscf_recipient_cipher_use_signer_hash(obj.cCtx, (*C.vscf_impl_t)(signerHash.ctx()))
}

/*
* Return true if a key recipient with a given id has been added.
* Note, operation has O(N) time complexity.
*/
func (obj *RecipientCipher) HasKeyRecipient(recipientId []byte) bool {
    recipientIdData := helperWrapData (recipientId)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_has_key_recipient(obj.cCtx, recipientIdData)

    return bool(proxyResult) /* r9 */
}

/*
* Add recipient defined with id and public key.
*/
func (obj *RecipientCipher) AddKeyRecipient(recipientId []byte, publicKey PublicKey) {
    recipientIdData := helperWrapData (recipientId)

    C.vscf_recipient_cipher_add_key_recipient(obj.cCtx, recipientIdData, (*C.vscf_impl_t)(publicKey.ctx()))

    return
}

/*
* Remove all recipients.
*/
func (obj *RecipientCipher) ClearRecipients() {
    C.vscf_recipient_cipher_clear_recipients(obj.cCtx)

    return
}

/*
* Add identifier and private key to sign initial plain text.
* Return error if the private key can not sign.
*/
func (obj *RecipientCipher) AddSigner(signerId []byte, privateKey PrivateKey) error {
    signerIdData := helperWrapData (signerId)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_add_signer(obj.cCtx, signerIdData, (*C.vscf_impl_t)(privateKey.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Remove all signers.
*/
func (obj *RecipientCipher) ClearSigners() {
    C.vscf_recipient_cipher_clear_signers(obj.cCtx)

    return
}

/*
* Provide access to the custom params object.
* The returned object can be used to add custom params or read it.
*/
func (obj *RecipientCipher) CustomParams() *MessageInfoCustomParams {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_custom_params(obj.cCtx)

    return newMessageInfoCustomParamsWithCtx(proxyResult) /* r5 */
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

    return nil
}

/*
* Start encryption process with known plain text size.
*
* Precondition: At least one signer should be added.
* Note, store message info footer as well.
*/
func (obj *RecipientCipher) StartSignedEncryption(dataSize uint32) error {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_signed_encryption(obj.cCtx, (C.size_t)(dataSize)/*pa10*/)

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
func (obj *RecipientCipher) MessageInfoLen() uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_message_info_len(obj.cCtx)

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
func (obj *RecipientCipher) PackMessageInfo() []byte {
    messageInfoBuf, messageInfoBufErr := bufferNewBuffer(int(obj.MessageInfoLen() /* lg2 */))
    if messageInfoBufErr != nil {
        return nil
    }
    defer messageInfoBuf.Delete()


    C.vscf_recipient_cipher_pack_message_info(obj.cCtx, messageInfoBuf.ctx)

    return messageInfoBuf.getData() /* r7 */
}

/*
* Return buffer length required to hold output of the method
* "process encryption" and method "finish" during encryption.
*/
func (obj *RecipientCipher) EncryptionOutLen(dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_encryption_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Process encryption of a new portion of data.
*/
func (obj *RecipientCipher) ProcessEncryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptionOutLen(uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_process_encryption(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Accomplish encryption.
*/
func (obj *RecipientCipher) FinishEncryption() ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptionOutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_recipient_cipher_finish_encryption(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Initiate decryption process with a recipient private key.
* Message Info can be empty if it was embedded to encrypted data.
*/
func (obj *RecipientCipher) StartDecryptionWithKey(recipientId []byte, privateKey PrivateKey, messageInfo []byte) error {
    recipientIdData := helperWrapData (recipientId)
    messageInfoData := helperWrapData (messageInfo)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_decryption_with_key(obj.cCtx, recipientIdData, (*C.vscf_impl_t)(privateKey.ctx()), messageInfoData)

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
func (obj *RecipientCipher) StartVerifiedDecryptionWithKey(recipientId []byte, privateKey PrivateKey, messageInfo []byte, messageInfoFooter []byte) error {
    recipientIdData := helperWrapData (recipientId)
    messageInfoData := helperWrapData (messageInfo)
    messageInfoFooterData := helperWrapData (messageInfoFooter)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_start_verified_decryption_with_key(obj.cCtx, recipientIdData, (*C.vscf_impl_t)(privateKey.ctx()), messageInfoData, messageInfoFooterData)

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
func (obj *RecipientCipher) DecryptionOutLen(dataLen uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_decryption_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Process with a new portion of data.
* Return error if data can not be encrypted or decrypted.
*/
func (obj *RecipientCipher) ProcessDecryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptionOutLen(uint32(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_recipient_cipher_process_decryption(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Accomplish decryption.
*/
func (obj *RecipientCipher) FinishDecryption() ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptionOutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_recipient_cipher_finish_decryption(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Return true if data was signed by a sender.
*
* Precondition: this method should be called after "finish decryption".
*/
func (obj *RecipientCipher) IsDataSigned() bool {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_is_data_signed(obj.cCtx)

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

    return newSignerInfoListWithCtx(proxyResult) /* r5 */
}

/*
* Verify given cipher info.
*/
func (obj *RecipientCipher) VerifySignerInfo(signerInfo *SignerInfo, publicKey PublicKey) bool {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_verify_signer_info(obj.cCtx, (*C.vscf_signer_info_t)(signerInfo.ctx()), (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold message footer returned by the
* "pack message footer" method.
*
* Precondition: this method should be called after "finish encryption".
*/
func (obj *RecipientCipher) MessageInfoFooterLen() uint32 {
    proxyResult := /*pr4*/C.vscf_recipient_cipher_message_info_footer_len(obj.cCtx)

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
func (obj *RecipientCipher) PackMessageInfoFooter() ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.MessageInfoFooterLen() /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_recipient_cipher_pack_message_info_footer(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}
