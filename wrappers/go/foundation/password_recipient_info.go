package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Handle information about recipient that is defined by a password.
*/
type PasswordRecipientInfo struct {
    cCtx *C.vscf_password_recipient_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *PasswordRecipientInfo) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewPasswordRecipientInfo() *PasswordRecipientInfo {
    ctx := C.vscf_password_recipient_info_new()
    obj := &PasswordRecipientInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPasswordRecipientInfoWithCtx(ctx *C.vscf_password_recipient_info_t /*ct2*/) *PasswordRecipientInfo {
    obj := &PasswordRecipientInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPasswordRecipientInfoCopy(ctx *C.vscf_password_recipient_info_t /*ct2*/) *PasswordRecipientInfo {
    obj := &PasswordRecipientInfo {
        cCtx: C.vscf_password_recipient_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *PasswordRecipientInfo) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.clear()
}

/*
* Release underlying C context.
*/
func (obj *PasswordRecipientInfo) delete() {
    C.vscf_password_recipient_info_delete(obj.cCtx)
}

/*
* Create object and define all properties.
*/
func NewPasswordRecipientInfoWithMembers(keyEncryptionAlgorithm AlgInfo, encryptedKey []byte) *PasswordRecipientInfo {
    encryptedKeyData := helperWrapData (encryptedKey)

    keyEncryptionAlgorithmCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(keyEncryptionAlgorithm.ctx()))

    proxyResult := /*pr4*/C.vscf_password_recipient_info_new_with_members(&keyEncryptionAlgorithmCopy, encryptedKeyData)

    obj := &PasswordRecipientInfo {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Return algorithm information that was used for encryption
* a data encryption key.
*/
func (obj *PasswordRecipientInfo) KeyEncryptionAlgorithm() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_key_encryption_algorithm(obj.cCtx)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Return an encrypted data encryption key.
*/
func (obj *PasswordRecipientInfo) EncryptedKey() []byte {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_encrypted_key(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}
