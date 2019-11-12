package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle information about recipient that is defined by a Public Key.
*/
type KeyRecipientInfo struct {
    cCtx *C.vscf_key_recipient_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyRecipientInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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

/*
* Release underlying C context.
*/
func (obj *KeyRecipientInfo) Delete () {
    C.vscf_key_recipient_info_delete(obj.cCtx)
}

/*
* Create object and define all properties.
*/
func NewKeyRecipientInfoWithData (recipientId []byte, keyEncryptionAlgorithm IAlgInfo, encryptedKey []byte) *KeyRecipientInfo {
    recipientIdData := helperWrapData (recipientId)
    encryptedKeyData := helperWrapData (encryptedKey)

    proxyResult := /*pr4*/C.vscf_key_recipient_info_new_with_data(recipientIdData, (*C.vscf_impl_t)(keyEncryptionAlgorithm.ctx()), encryptedKeyData)

    return &KeyRecipientInfo {
        cCtx: proxyResult,
    }
}

/*
* Return recipient identifier.
*/
func (obj *KeyRecipientInfo) RecipientId () []byte {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_recipient_id(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm information that was used for encryption
* a data encryption key.
*/
func (obj *KeyRecipientInfo) KeyEncryptionAlgorithm () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_key_encryption_algorithm(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return an encrypted data encryption key.
*/
func (obj *KeyRecipientInfo) EncryptedKey () []byte {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_encrypted_key(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}
