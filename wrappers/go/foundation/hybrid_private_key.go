package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles a hybrid private key.
*
* The hybrid private key contains 2 private keys.
*/
type HybridPrivateKey struct {
    cCtx *C.vscf_hybrid_private_key_t /*ct10*/
}

/*
* Return first private key.
*/
func (obj *HybridPrivateKey) FirstKey() (PrivateKey, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_first_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4.1 */
}

/*
* Return second private key.
*/
func (obj *HybridPrivateKey) SecondKey() (PrivateKey, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_second_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4.1 */
}

/* Handle underlying C context. */
func (obj *HybridPrivateKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHybridPrivateKey() *HybridPrivateKey {
    ctx := C.vscf_hybrid_private_key_new()
    obj := &HybridPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridPrivateKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridPrivateKeyWithCtx(ctx *C.vscf_hybrid_private_key_t /*ct10*/) *HybridPrivateKey {
    obj := &HybridPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridPrivateKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridPrivateKeyCopy(ctx *C.vscf_hybrid_private_key_t /*ct10*/) *HybridPrivateKey {
    obj := &HybridPrivateKey {
        cCtx: C.vscf_hybrid_private_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*HybridPrivateKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *HybridPrivateKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *HybridPrivateKey) delete() {
    C.vscf_hybrid_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *HybridPrivateKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *HybridPrivateKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4.1 */
}

/*
* Length of the key in bytes.
*/
func (obj *HybridPrivateKey) Len() uint {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *HybridPrivateKey) Bitlen() uint {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *HybridPrivateKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *HybridPrivateKey) ExtractPublicKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_private_key_extract_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4.1 */
}
