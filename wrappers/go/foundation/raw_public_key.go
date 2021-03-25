package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles interchangeable public key representation.
*/
type RawPublicKey struct {
    cCtx *C.vscf_raw_public_key_t /*ct10*/
}

/*
* Return key data.
*/
func (obj *RawPublicKey) Data() []byte {
    proxyResult := /*pr4*/C.vscf_raw_public_key_data(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/* Handle underlying C context. */
func (obj *RawPublicKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRawPublicKey() *RawPublicKey {
    ctx := C.vscf_raw_public_key_new()
    obj := &RawPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawPublicKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawPublicKeyWithCtx(pointer unsafe.Pointer) *RawPublicKey {
    ctx := (*C.vscf_raw_public_key_t /*ct10*/)(pointer)
    obj := &RawPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawPublicKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawPublicKeyCopy(pointer unsafe.Pointer) *RawPublicKey {
    ctx := (*C.vscf_raw_public_key_t /*ct10*/)(pointer)
    obj := &RawPublicKey {
        cCtx: C.vscf_raw_public_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RawPublicKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RawPublicKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RawPublicKey) delete() {
    C.vscf_raw_public_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *RawPublicKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_raw_public_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *RawPublicKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_raw_public_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfoCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/*
* Length of the key in bytes.
*/
func (obj *RawPublicKey) Len() uint {
    proxyResult := /*pr4*/C.vscf_raw_public_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *RawPublicKey) Bitlen() uint {
    proxyResult := /*pr4*/C.vscf_raw_public_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *RawPublicKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_raw_public_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
