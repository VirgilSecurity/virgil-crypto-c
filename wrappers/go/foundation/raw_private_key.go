package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles interchangeable private key representation.
*/
type RawPrivateKey struct {
    cCtx *C.vscf_raw_private_key_t /*ct10*/
}

/*
* Return key data.
*/
func (obj *RawPrivateKey) Data() []byte {
    proxyResult := /*pr4*/C.vscf_raw_private_key_data(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return true if private key contains public key.
*/
func (obj *RawPrivateKey) HasPublicKey() bool {
    proxyResult := /*pr4*/C.vscf_raw_private_key_has_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Setup public key related to the private key.
*/
func (obj *RawPrivateKey) SetPublicKey(rawPublicKey *RawPublicKey) {
    rawPublicKeyCopy := C.vscf_raw_public_key_shallow_copy((*C.vscf_raw_public_key_t)(unsafe.Pointer(rawPublicKey.Ctx())))

    C.vscf_raw_private_key_set_public_key(obj.cCtx, &rawPublicKeyCopy)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawPublicKey)

    return
}

/*
* Return public key related to the private key.
*/
func (obj *RawPrivateKey) GetPublicKey() *RawPublicKey {
    proxyResult := /*pr4*/C.vscf_raw_private_key_get_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return newRawPublicKeyCopy(proxyResult) /* r5 */
}

/* Handle underlying C context. */
func (obj *RawPrivateKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRawPrivateKey() *RawPrivateKey {
    ctx := C.vscf_raw_private_key_new()
    obj := &RawPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawPrivateKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawPrivateKeyWithCtx(ctx *C.vscf_raw_private_key_t /*ct10*/) *RawPrivateKey {
    obj := &RawPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawPrivateKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawPrivateKeyCopy(ctx *C.vscf_raw_private_key_t /*ct10*/) *RawPrivateKey {
    obj := &RawPrivateKey {
        cCtx: C.vscf_raw_private_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RawPrivateKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RawPrivateKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RawPrivateKey) delete() {
    C.vscf_raw_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *RawPrivateKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_raw_private_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *RawPrivateKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_raw_private_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4.1 */
}

/*
* Length of the key in bytes.
*/
func (obj *RawPrivateKey) Len() uint {
    proxyResult := /*pr4*/C.vscf_raw_private_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *RawPrivateKey) Bitlen() uint {
    proxyResult := /*pr4*/C.vscf_raw_private_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *RawPrivateKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_raw_private_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *RawPrivateKey) ExtractPublicKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_raw_private_key_extract_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}
