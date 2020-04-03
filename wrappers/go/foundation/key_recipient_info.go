package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle information about recipient that is defined by a Public Key.
*/
type KeyRecipientInfo struct {
    cCtx *C.vscf_key_recipient_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyRecipientInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyRecipientInfo() *KeyRecipientInfo {
    ctx := C.vscf_key_recipient_info_new()
    obj := &KeyRecipientInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyRecipientInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyRecipientInfoWithCtx(ctx *C.vscf_key_recipient_info_t /*ct2*/) *KeyRecipientInfo {
    obj := &KeyRecipientInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyRecipientInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyRecipientInfoCopy(ctx *C.vscf_key_recipient_info_t /*ct2*/) *KeyRecipientInfo {
    obj := &KeyRecipientInfo {
        cCtx: C.vscf_key_recipient_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KeyRecipientInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyRecipientInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyRecipientInfo) delete() {
    C.vscf_key_recipient_info_delete(obj.cCtx)
}

/*
* Create object and define all properties.
*/
func NewKeyRecipientInfoWithData(recipientId []byte, keyEncryptionAlgorithm AlgInfo, encryptedKey []byte) *KeyRecipientInfo {
    recipientIdData := helperWrapData (recipientId)
    encryptedKeyData := helperWrapData (encryptedKey)

    proxyResult := /*pr4*/C.vscf_key_recipient_info_new_with_data(recipientIdData, (*C.vscf_impl_t)(unsafe.Pointer(keyEncryptionAlgorithm.Ctx())), encryptedKeyData)

    runtime.KeepAlive(keyEncryptionAlgorithm)

    obj := &KeyRecipientInfo {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*KeyRecipientInfo).Delete)
    return obj
}

/*
* Return recipient identifier.
*/
func (obj *KeyRecipientInfo) RecipientId() []byte {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_recipient_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm information that was used for encryption
* a data encryption key.
*/
func (obj *KeyRecipientInfo) KeyEncryptionAlgorithm() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_key_encryption_algorithm(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4.1 */
}

/*
* Return an encrypted data encryption key.
*/
func (obj *KeyRecipientInfo) EncryptedKey() []byte {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_encrypted_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}
