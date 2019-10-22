package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* This class provides hybrid encryption algorithm that combines symmetric
* cipher for data encryption and asymmetric cipher and password based
* cipher for symmetric key encryption.
*/
type RecipientCipher struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this RecipientCipher) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewRecipientCipher () *RecipientCipher {
    ctx := C.vscf_recipient_cipher_new()
    return &RecipientCipher {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRecipientCipherWithCtx (ctx *C.vscf_impl_t) *RecipientCipher {
    return &RecipientCipher {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRecipientCipherCopy (ctx *C.vscf_impl_t) *RecipientCipher {
    return &RecipientCipher {
        ctx: C.vscf_recipient_cipher_shallow_copy(ctx),
    }
}

func (this RecipientCipher) SetRandom (random IRandom) {
    C.vscf_recipient_cipher_release_random(this.ctx)
    C.vscf_recipient_cipher_use_random(this.ctx, random.Ctx())
}

func (this RecipientCipher) SetEncryptionCipher (encryptionCipher ICipher) {
    C.vscf_recipient_cipher_release_encryption_cipher(this.ctx)
    C.vscf_recipient_cipher_use_encryption_cipher(this.ctx, encryptionCipher.Ctx())
}

func (this RecipientCipher) SetSignerHash (signerHash IHash) {
    C.vscf_recipient_cipher_release_signer_hash(this.ctx)
    C.vscf_recipient_cipher_use_signer_hash(this.ctx, signerHash.Ctx())
}

/*
* Return true if a key recipient with a given id has been added.
* Note, operation has O(N) time complexity.
*/
func (this RecipientCipher) HasKeyRecipient (recipientId []byte) bool {
    proxyResult := C.vscf_recipient_cipher_has_key_recipient(this.ctx, WrapData(recipientId))

    return proxyResult //r9
}

/*
* Add recipient defined with id and public key.
*/
func (this RecipientCipher) AddKeyRecipient (recipientId []byte, publicKey IPublicKey) {
    C.vscf_recipient_cipher_add_key_recipient(this.ctx, WrapData(recipientId), publicKey.Ctx())
}

/*
* Remove all recipients.
*/
func (this RecipientCipher) ClearRecipients () {
    C.vscf_recipient_cipher_clear_recipients(this.ctx)
}

/*
* Add identifier and private key to sign initial plain text.
* Return error if the private key can not sign.
*/
func (this RecipientCipher) AddSigner (signerId []byte, privateKey IPrivateKey) {
    proxyResult := C.vscf_recipient_cipher_add_signer(this.ctx, WrapData(signerId), privateKey.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Remove all signers.
*/
func (this RecipientCipher) ClearSigners () {
    C.vscf_recipient_cipher_clear_signers(this.ctx)
}

/*
* Provide access to the custom params object.
* The returned object can be used to add custom params or read it.
*/
func (this RecipientCipher) CustomParams () MessageInfoCustomParams {
    proxyResult := C.vscf_recipient_cipher_custom_params(this.ctx)

    return MessageInfoCustomParams(proxyResult) /* r5 */
}

/*
* Start encryption process.
*/
func (this RecipientCipher) StartEncryption () {
    proxyResult := C.vscf_recipient_cipher_start_encryption(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Start encryption process with known plain text size.
*
* Precondition: At least one signer should be added.
* Note, store message info footer as well.
*/
func (this RecipientCipher) StartSignedEncryption (dataSize int32) {
    proxyResult := C.vscf_recipient_cipher_start_signed_encryption(this.ctx, dataSize)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Return buffer length required to hold message info returned by the
* "pack message info" method.
* Precondition: all recipients and custom parameters should be set.
*/
func (this RecipientCipher) MessageInfoLen () int32 {
    proxyResult := C.vscf_recipient_cipher_message_info_len(this.ctx)

    return proxyResult //r9
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
    messageInfoCount := this.MessageInfoLen() /* lg2 */
    messageInfoBuf := NewBuffer(messageInfoCount)
    defer messageInfoBuf.Clear()


    C.vscf_recipient_cipher_pack_message_info(this.ctx, messageInfoBuf)

    return messageInfoBuf.GetData() /* r7 */
}

/*
* Return buffer length required to hold output of the method
* "process encryption" and method "finish" during encryption.
*/
func (this RecipientCipher) EncryptionOutLen (dataLen int32) int32 {
    proxyResult := C.vscf_recipient_cipher_encryption_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Process encryption of a new portion of data.
*/
func (this RecipientCipher) ProcessEncryption (data []byte) []byte {
    outCount := this.EncryptionOutLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_recipient_cipher_process_encryption(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Accomplish encryption.
*/
func (this RecipientCipher) FinishEncryption () []byte {
    outCount := this.EncryptionOutLen(0) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_recipient_cipher_finish_encryption(this.ctx, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Initiate decryption process with a recipient private key.
* Message Info can be empty if it was embedded to encrypted data.
*/
func (this RecipientCipher) StartDecryptionWithKey (recipientId []byte, privateKey IPrivateKey, messageInfo []byte) {
    proxyResult := C.vscf_recipient_cipher_start_decryption_with_key(this.ctx, WrapData(recipientId), privateKey.Ctx(), WrapData(messageInfo))

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Initiate decryption process with a recipient private key.
* Message Info can be empty if it was embedded to encrypted data.
* Message Info footer can be empty if it was embedded to encrypted data.
* If footer was embedded, method "start decryption with key" can be used.
*/
func (this RecipientCipher) StartVerifiedDecryptionWithKey (recipientId []byte, privateKey IPrivateKey, messageInfo []byte, messageInfoFooter []byte) {
    proxyResult := C.vscf_recipient_cipher_start_verified_decryption_with_key(this.ctx, WrapData(recipientId), privateKey.Ctx(), WrapData(messageInfo), WrapData(messageInfoFooter))

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Return buffer length required to hold output of the method
* "process decryption" and method "finish" during decryption.
*/
func (this RecipientCipher) DecryptionOutLen (dataLen int32) int32 {
    proxyResult := C.vscf_recipient_cipher_decryption_out_len(this.ctx, dataLen)

    return proxyResult //r9
}

/*
* Process with a new portion of data.
* Return error if data can not be encrypted or decrypted.
*/
func (this RecipientCipher) ProcessDecryption (data []byte) []byte {
    outCount := this.DecryptionOutLen(int32(len(data))) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_recipient_cipher_process_decryption(this.ctx, WrapData(data), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Accomplish decryption.
*/
func (this RecipientCipher) FinishDecryption () []byte {
    outCount := this.DecryptionOutLen(0) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_recipient_cipher_finish_decryption(this.ctx, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Return true if data was signed by a sender.
*
* Precondition: this method should be called after "finish decryption".
*/
func (this RecipientCipher) IsDataSigned () bool {
    proxyResult := C.vscf_recipient_cipher_is_data_signed(this.ctx)

    return proxyResult //r9
}

/*
* Return information about signers that sign data.
*
* Precondition: this method should be called after "finish decryption".
* Precondition: method "is data signed" returns true.
*/
func (this RecipientCipher) SignerInfos () SignerInfoList {
    proxyResult := C.vscf_recipient_cipher_signer_infos(this.ctx)

    return SignerInfoList(proxyResult) /* r5 */
}

/*
* Verify given cipher info.
*/
func (this RecipientCipher) VerifySignerInfo (signerInfo SignerInfo, publicKey IPublicKey) bool {
    proxyResult := C.vscf_recipient_cipher_verify_signer_info(this.ctx, signerInfo.Ctx(), publicKey.Ctx())

    return proxyResult //r9
}

/*
* Return buffer length required to hold message footer returned by the
* "pack message footer" method.
*
* Precondition: this method should be called after "finish encryption".
*/
func (this RecipientCipher) MessageInfoFooterLen () int32 {
    proxyResult := C.vscf_recipient_cipher_message_info_footer_len(this.ctx)

    return proxyResult //r9
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
func (this RecipientCipher) PackMessageInfoFooter () []byte {
    outCount := this.MessageInfoFooterLen() /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_recipient_cipher_pack_message_info_footer(this.ctx, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
