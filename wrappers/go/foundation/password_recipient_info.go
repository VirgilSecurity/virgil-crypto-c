package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handle information about recipient that is defined by a password.
*/
type PasswordRecipientInfo struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this PasswordRecipientInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewPasswordRecipientInfo () *PasswordRecipientInfo {
    ctx := C.vscf_password_recipient_info_new()
    return &PasswordRecipientInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPasswordRecipientInfoWithCtx (ctx *C.vscf_impl_t) *PasswordRecipientInfo {
    return &PasswordRecipientInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPasswordRecipientInfoCopy (ctx *C.vscf_impl_t) *PasswordRecipientInfo {
    return &PasswordRecipientInfo {
        ctx: C.vscf_password_recipient_info_shallow_copy(ctx),
    }
}

/*
* Create object and define all properties.
*/
func NewPasswordRecipientInfowithMembers (keyEncryptionAlgorithm IAlgInfo, encryptedKey []byte) *PasswordRecipientInfo {
    keyEncryptionAlgorithmCopy := C.vscf_impl_shallow_copy(keyEncryptionAlgorithm.Ctx())

    proxyResult := C.vscf_password_recipient_info_new_with_members(&keyEncryptionAlgorithmCopy, WrapData(encryptedKey))

    return &PasswordRecipientInfo {
        ctx: proxyResult,
    }
}

/*
* Return algorithm information that was used for encryption
* a data encryption key.
*/
func (this PasswordRecipientInfo) KeyEncryptionAlgorithm () IAlgInfo {
    proxyResult := C.vscf_password_recipient_info_key_encryption_algorithm(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return an encrypted data encryption key.
*/
func (this PasswordRecipientInfo) EncryptedKey () []byte {
    proxyResult := C.vscf_password_recipient_info_encrypted_key(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}
