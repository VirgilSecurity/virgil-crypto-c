package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle information about an encrypted message and algorithms
* that was used for encryption.
*/
type MessageInfo struct {
    cCtx *C.vscf_message_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessageInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessageInfo() *MessageInfo {
    ctx := C.vscf_message_info_new()
    obj := &MessageInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessageInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoWithCtx(pointer unsafe.Pointer) *MessageInfo {
    ctx := (*C.vscf_message_info_t /*ct2*/)(pointer)
    obj := &MessageInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessageInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoCopy(pointer unsafe.Pointer) *MessageInfo {
    ctx := (*C.vscf_message_info_t /*ct2*/)(pointer)
    obj := &MessageInfo {
        cCtx: C.vscf_message_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessageInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessageInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessageInfo) delete() {
    C.vscf_message_info_delete(obj.cCtx)
}

/*
* Return information about algorithm that was used for the data encryption.
*/
func (obj *MessageInfo) DataEncryptionAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_message_info_data_encryption_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfoCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/*
* Return list with a "key recipient info" elements.
*/
func (obj *MessageInfo) KeyRecipientInfoList() *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_message_info_key_recipient_info_list(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewKeyRecipientInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return list with a "password recipient info" elements.
*/
func (obj *MessageInfo) PasswordRecipientInfoList() *PasswordRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_message_info_password_recipient_info_list(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewPasswordRecipientInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if message info contains at least one custom param.
*/
func (obj *MessageInfo) HasCustomParams() bool {
    proxyResult := /*pr4*/C.vscf_message_info_has_custom_params(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Provide access to the custom params object.
* The returned object can be used to add custom params or read it.
* If custom params object was not set then new empty object is created.
*/
func (obj *MessageInfo) CustomParams() *MessageInfoCustomParams {
    proxyResult := /*pr4*/C.vscf_message_info_custom_params(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessageInfoCustomParamsCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if cipher kdf alg info exists.
*/
func (obj *MessageInfo) HasCipherKdfAlgInfo() bool {
    proxyResult := /*pr4*/C.vscf_message_info_has_cipher_kdf_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return cipher kdf alg info.
*/
func (obj *MessageInfo) CipherKdfAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_message_info_cipher_kdf_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfoCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/*
* Return true if cipher padding alg info exists.
*/
func (obj *MessageInfo) HasCipherPaddingAlgInfo() bool {
    proxyResult := /*pr4*/C.vscf_message_info_has_cipher_padding_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return cipher padding alg info.
*/
func (obj *MessageInfo) CipherPaddingAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_message_info_cipher_padding_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfoCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/*
* Return true if footer info exists.
*/
func (obj *MessageInfo) HasFooterInfo() bool {
    proxyResult := /*pr4*/C.vscf_message_info_has_footer_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return footer info.
*/
func (obj *MessageInfo) FooterInfo() *FooterInfo {
    proxyResult := /*pr4*/C.vscf_message_info_footer_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewFooterInfoCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Remove all infos.
*/
func (obj *MessageInfo) Clear() {
    C.vscf_message_info_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}
