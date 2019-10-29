package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle information about recipient that is defined by a Public Key.
*/
type KeyRecipientInfo struct {
    cCtx *C.vscf_key_recipient_info_t /*ct2*/
}

/* Handle underlying C context. */
func (this KeyRecipientInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewKeyRecipientInfo () *KeyRecipientInfo {
    ctx := C.vscf_key_recipient_info_new()
    return &KeyRecipientInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyRecipientInfoWithCtx (ctx *C.vscf_key_recipient_info_t /*ct2*/) *KeyRecipientInfo {
    return &KeyRecipientInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyRecipientInfoCopy (ctx *C.vscf_key_recipient_info_t /*ct2*/) *KeyRecipientInfo {
    return &KeyRecipientInfo {
        cCtx: C.vscf_key_recipient_info_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this KeyRecipientInfo) close () {
    C.vscf_key_recipient_info_delete(this.cCtx)
}

/*
* Create object and define all properties.
*/
func NewKeyRecipientInfoWithData (recipientId []byte, keyEncryptionAlgorithm IAlgInfo, encryptedKey []byte) *KeyRecipientInfo {
    recipientIdData := C.vsc_data((*C.uint8_t)(&recipientId[0]), C.size_t(len(recipientId)))
    encryptedKeyData := C.vsc_data((*C.uint8_t)(&encryptedKey[0]), C.size_t(len(encryptedKey)))

    proxyResult := /*pr4*/C.vscf_key_recipient_info_new_with_data(recipientIdData, (*C.vscf_impl_t)(keyEncryptionAlgorithm.ctx()), encryptedKeyData)

    return &KeyRecipientInfo {
        cCtx: proxyResult,
    }
}

/*
* Return recipient identifier.
*/
func (this KeyRecipientInfo) RecipientId () []byte {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_recipient_id(this.cCtx)

    return helperDataToBytes(proxyResult) /* r1 */
}

/*
* Return algorithm information that was used for encryption
* a data encryption key.
*/
func (this KeyRecipientInfo) KeyEncryptionAlgorithm () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_key_encryption_algorithm(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return an encrypted data encryption key.
*/
func (this KeyRecipientInfo) EncryptedKey () []byte {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_encrypted_key(this.cCtx)

    return helperDataToBytes(proxyResult) /* r1 */
}
