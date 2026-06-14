package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle information about recipient that uses a pre-shared symmetric Key Encryption Key (KEK).
* Follows RFC 5652 KEKRecipientInfo structure.
*/
type KekRecipientInfo struct {
    cCtx *C.vscf_kek_recipient_info_t
}

/* Handle underlying C context. */
func (obj *KekRecipientInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKekRecipientInfo() *KekRecipientInfo {
    ctx := C.vscf_kek_recipient_info_new()
    obj := &KekRecipientInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KekRecipientInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKekRecipientInfoWithCtx(ctx *C.vscf_kek_recipient_info_t) *KekRecipientInfo {
    obj := &KekRecipientInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KekRecipientInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKekRecipientInfoCopy(ctx *C.vscf_kek_recipient_info_t) *KekRecipientInfo {
    obj := &KekRecipientInfo {
        cCtx: C.vscf_kek_recipient_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KekRecipientInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KekRecipientInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KekRecipientInfo) delete() {
    C.vscf_kek_recipient_info_delete(obj.cCtx)
}

/*
* Create object and define all properties.
*/
func NewKekRecipientInfoWithMembers(kekId []byte, keyEncryptionAlgorithm AlgInfo, encryptedKey []byte) *KekRecipientInfo {
    keyEncryptionAlgorithmCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(unsafe.Pointer(keyEncryptionAlgorithm.Ctx())))
    kekIdData := helperWrapData (kekId)
    encryptedKeyData := helperWrapData (encryptedKey)

    proxyResult := C.vscf_kek_recipient_info_new_with_members(kekIdData, &keyEncryptionAlgorithmCopy, encryptedKeyData)

    runtime.KeepAlive(keyEncryptionAlgorithm)

    obj := &KekRecipientInfo {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*KekRecipientInfo).Delete)
    return obj
}

/*
* Return KEK identifier.
*/
func (obj *KekRecipientInfo) KekId() []byte {
    proxyResult := C.vscf_kek_recipient_info_kek_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/*
* Return algorithm information that was used for encrypting the data encryption key.
*/
func (obj *KekRecipientInfo) KeyEncryptionAlgorithm() (AlgInfo, error) {
    proxyResult := C.vscf_kek_recipient_info_key_encryption_algorithm(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult)
}

/*
* Return an encrypted data encryption key.
*/
func (obj *KekRecipientInfo) EncryptedKey() []byte {
    proxyResult := C.vscf_kek_recipient_info_encrypted_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}
