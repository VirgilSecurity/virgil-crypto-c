package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle information about an encrypted message and algorithms
* that was used for encryption.
*/
type MessageInfo struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this MessageInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewMessageInfo () *MessageInfo {
    ctx := C.vscf_message_info_new()
    return &MessageInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoWithCtx (ctx *C.vscf_impl_t) *MessageInfo {
    return &MessageInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoCopy (ctx *C.vscf_impl_t) *MessageInfo {
    return &MessageInfo {
        ctx: C.vscf_message_info_shallow_copy(ctx),
    }
}

/*
* Return information about algorithm that was used for the data encryption.
*/
func (this MessageInfo) DataEncryptionAlgInfo () IAlgInfo {
    proxyResult := C.vscf_message_info_data_encryption_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return list with a "key recipient info" elements.
*/
func (this MessageInfo) KeyRecipientInfoList () KeyRecipientInfoList {
    proxyResult := C.vscf_message_info_key_recipient_info_list(this.ctx)

    return KeyRecipientInfoList(proxyResult) /* r5 */
}

/*
* Return list with a "password recipient info" elements.
*/
func (this MessageInfo) PasswordRecipientInfoList () PasswordRecipientInfoList {
    proxyResult := C.vscf_message_info_password_recipient_info_list(this.ctx)

    return PasswordRecipientInfoList(proxyResult) /* r5 */
}

/*
* Return true if message info contains at least one custom param.
*/
func (this MessageInfo) HasCustomParams () bool {
    proxyResult := C.vscf_message_info_has_custom_params(this.ctx)

    return proxyResult //r9
}

/*
* Provide access to the custom params object.
* The returned object can be used to add custom params or read it.
* If custom params object was not set then new empty object is created.
*/
func (this MessageInfo) CustomParams () MessageInfoCustomParams {
    proxyResult := C.vscf_message_info_custom_params(this.ctx)

    return MessageInfoCustomParams(proxyResult) /* r5 */
}

/*
* Return true if cipher kdf alg info exists.
*/
func (this MessageInfo) HasCipherKdfAlgInfo () bool {
    proxyResult := C.vscf_message_info_has_cipher_kdf_alg_info(this.ctx)

    return proxyResult //r9
}

/*
* Return cipher kdf alg info.
*/
func (this MessageInfo) CipherKdfAlgInfo () IAlgInfo {
    proxyResult := C.vscf_message_info_cipher_kdf_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return true if footer info exists.
*/
func (this MessageInfo) HasFooterInfo () bool {
    proxyResult := C.vscf_message_info_has_footer_info(this.ctx)

    return proxyResult //r9
}

/*
* Return footer info.
*/
func (this MessageInfo) FooterInfo () FooterInfo {
    proxyResult := C.vscf_message_info_footer_info(this.ctx)

    return FooterInfo(proxyResult) /* r5 */
}

/*
* Remove all infos.
*/
func (this MessageInfo) Clear () {
    C.vscf_message_info_clear(this.ctx)
}
