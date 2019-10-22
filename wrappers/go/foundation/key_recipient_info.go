package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handle information about recipient that is defined by a Public Key.
*/
type KeyRecipientInfo struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this KeyRecipientInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewKeyRecipientInfo () *KeyRecipientInfo {
    ctx := C.vscf_key_recipient_info_new()
    return &KeyRecipientInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyRecipientInfoWithCtx (ctx *C.vscf_impl_t) *KeyRecipientInfo {
    return &KeyRecipientInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyRecipientInfoCopy (ctx *C.vscf_impl_t) *KeyRecipientInfo {
    return &KeyRecipientInfo {
        ctx: C.vscf_key_recipient_info_shallow_copy(ctx),
    }
}

/*
* Create object and define all properties.
*/
func NewKeyRecipientInfowithData (recipientId []byte, keyEncryptionAlgorithm IAlgInfo, encryptedKey []byte) *KeyRecipientInfo {
    proxyResult := C.vscf_key_recipient_info_new_with_data(WrapData(recipientId), keyEncryptionAlgorithm.Ctx(), WrapData(encryptedKey))

    return &KeyRecipientInfo {
        ctx: proxyResult,
    }
}

/*
* Return recipient identifier.
*/
func (this KeyRecipientInfo) RecipientId () []byte {
    proxyResult := C.vscf_key_recipient_info_recipient_id(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm information that was used for encryption
* a data encryption key.
*/
func (this KeyRecipientInfo) KeyEncryptionAlgorithm () IAlgInfo {
    proxyResult := C.vscf_key_recipient_info_key_encryption_algorithm(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return an encrypted data encryption key.
*/
func (this KeyRecipientInfo) EncryptedKey () []byte {
    proxyResult := C.vscf_key_recipient_info_encrypted_key(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}
