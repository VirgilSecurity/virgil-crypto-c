package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle information about recipient that is defined by a password.
*/
type PasswordRecipientInfo struct {
    cCtx *C.vscf_password_recipient_info_t /*ct2*/
}

/* Handle underlying C context. */
func (this PasswordRecipientInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewPasswordRecipientInfo () *PasswordRecipientInfo {
    ctx := C.vscf_password_recipient_info_new()
    return &PasswordRecipientInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPasswordRecipientInfoWithCtx (ctx *C.vscf_password_recipient_info_t /*ct2*/) *PasswordRecipientInfo {
    return &PasswordRecipientInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPasswordRecipientInfoCopy (ctx *C.vscf_password_recipient_info_t /*ct2*/) *PasswordRecipientInfo {
    return &PasswordRecipientInfo {
        cCtx: C.vscf_password_recipient_info_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this PasswordRecipientInfo) close () {
    C.vscf_password_recipient_info_delete(this.cCtx)
}

/*
* Create object and define all properties.
*/
func NewPasswordRecipientInfoWithMembers (keyEncryptionAlgorithm IAlgInfo, encryptedKey []byte) *PasswordRecipientInfo {
    encryptedKeyData := C.vsc_data((*C.uint8_t)(&encryptedKey[0]), C.size_t(len(encryptedKey)))

    keyEncryptionAlgorithmCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(keyEncryptionAlgorithm.ctx()))

    proxyResult := /*pr4*/C.vscf_password_recipient_info_new_with_members(&keyEncryptionAlgorithmCopy, encryptedKeyData)

    return &PasswordRecipientInfo {
        cCtx: proxyResult,
    }
}

/*
* Return algorithm information that was used for encryption
* a data encryption key.
*/
func (this PasswordRecipientInfo) KeyEncryptionAlgorithm () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_key_encryption_algorithm(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return an encrypted data encryption key.
*/
func (this PasswordRecipientInfo) EncryptedKey () []byte {
    proxyResult := /*pr4*/C.vscf_password_recipient_info_encrypted_key(this.cCtx)

    return helperDataToBytes(proxyResult) /* r1 */
}
