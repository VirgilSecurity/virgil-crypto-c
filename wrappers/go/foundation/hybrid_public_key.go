package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles a hybrid public key.
*
* The hybrid public key contains 2 public keys.
*/
type HybridPublicKey struct {
    cCtx *C.vscf_hybrid_public_key_t /*ct10*/
}

/*
* Return the first public key.
*/
func (obj *HybridPublicKey) FirstKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_public_key_first_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Return the second public key.
*/
func (obj *HybridPublicKey) SecondKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_public_key_second_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *HybridPublicKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHybridPublicKey() *HybridPublicKey {
    ctx := C.vscf_hybrid_public_key_new()
    obj := &HybridPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridPublicKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridPublicKeyWithCtx(ctx *C.vscf_hybrid_public_key_t /*ct10*/) *HybridPublicKey {
    obj := &HybridPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridPublicKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridPublicKeyCopy(ctx *C.vscf_hybrid_public_key_t /*ct10*/) *HybridPublicKey {
    obj := &HybridPublicKey {
        cCtx: C.vscf_hybrid_public_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*HybridPublicKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *HybridPublicKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *HybridPublicKey) delete() {
    C.vscf_hybrid_public_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *HybridPublicKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_hybrid_public_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *HybridPublicKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_public_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *HybridPublicKey) Len() uint32 {
    proxyResult := /*pr4*/C.vscf_hybrid_public_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *HybridPublicKey) Bitlen() uint32 {
    proxyResult := /*pr4*/C.vscf_hybrid_public_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *HybridPublicKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_hybrid_public_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
