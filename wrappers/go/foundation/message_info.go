package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle information about an encrypted message and algorithms
* that was used for encryption.
*/
type MessageInfo struct {
    cCtx *C.vscf_message_info_t /*ct2*/
}

/* Handle underlying C context. */
func (this MessageInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewMessageInfo () *MessageInfo {
    ctx := C.vscf_message_info_new()
    return &MessageInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoWithCtx (ctx *C.vscf_message_info_t /*ct2*/) *MessageInfo {
    return &MessageInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoCopy (ctx *C.vscf_message_info_t /*ct2*/) *MessageInfo {
    return &MessageInfo {
        cCtx: C.vscf_message_info_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this MessageInfo) close () {
    C.vscf_message_info_delete(this.cCtx)
}

/*
* Return information about algorithm that was used for the data encryption.
*/
func (this MessageInfo) DataEncryptionAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_message_info_data_encryption_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return list with a "key recipient info" elements.
*/
func (this MessageInfo) KeyRecipientInfoList () *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_message_info_key_recipient_info_list(this.cCtx)

    return newKeyRecipientInfoListWithCtx(proxyResult) /* r5 */
}

/*
* Return list with a "password recipient info" elements.
*/
func (this MessageInfo) PasswordRecipientInfoList () *PasswordRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_message_info_password_recipient_info_list(this.cCtx)

    return newPasswordRecipientInfoListWithCtx(proxyResult) /* r5 */
}

/*
* Return true if message info contains at least one custom param.
*/
func (this MessageInfo) HasCustomParams () bool {
    proxyResult := /*pr4*/C.vscf_message_info_has_custom_params(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Provide access to the custom params object.
* The returned object can be used to add custom params or read it.
* If custom params object was not set then new empty object is created.
*/
func (this MessageInfo) CustomParams () *MessageInfoCustomParams {
    proxyResult := /*pr4*/C.vscf_message_info_custom_params(this.cCtx)

    return newMessageInfoCustomParamsWithCtx(proxyResult) /* r5 */
}

/*
* Return true if cipher kdf alg info exists.
*/
func (this MessageInfo) HasCipherKdfAlgInfo () bool {
    proxyResult := /*pr4*/C.vscf_message_info_has_cipher_kdf_alg_info(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return cipher kdf alg info.
*/
func (this MessageInfo) CipherKdfAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_message_info_cipher_kdf_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return true if footer info exists.
*/
func (this MessageInfo) HasFooterInfo () bool {
    proxyResult := /*pr4*/C.vscf_message_info_has_footer_info(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return footer info.
*/
func (this MessageInfo) FooterInfo () *FooterInfo {
    proxyResult := /*pr4*/C.vscf_message_info_footer_info(this.cCtx)

    return newFooterInfoWithCtx(proxyResult) /* r5 */
}

/*
* Remove all infos.
*/
func (this MessageInfo) Clear () {
    C.vscf_message_info_clear(this.cCtx)

    return
}
