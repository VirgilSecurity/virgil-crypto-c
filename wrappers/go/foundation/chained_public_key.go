package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles chained public key.
*
* Chained public key contains 2 public keys:
* - l1 key:
* - can be used for plain text encryption;
* - can be used to verify l1 signature;
* - l2 key:
* - can be used for l1 output encryption;
* - can be used to verify l2 signature.
*/
type ChainedPublicKey struct {
    cCtx *C.vscf_chained_public_key_t /*ct10*/
}

/*
* Return l1 public key.
*/
func (obj *ChainedPublicKey) L1Key() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_chained_public_key_l1_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Return l2 public key.
*/
func (obj *ChainedPublicKey) L2Key() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_chained_public_key_l2_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *ChainedPublicKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewChainedPublicKey() *ChainedPublicKey {
    ctx := C.vscf_chained_public_key_new()
    obj := &ChainedPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChainedPublicKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChainedPublicKeyWithCtx(ctx *C.vscf_chained_public_key_t /*ct10*/) *ChainedPublicKey {
    obj := &ChainedPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChainedPublicKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChainedPublicKeyCopy(ctx *C.vscf_chained_public_key_t /*ct10*/) *ChainedPublicKey {
    obj := &ChainedPublicKey {
        cCtx: C.vscf_chained_public_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*ChainedPublicKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *ChainedPublicKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *ChainedPublicKey) delete() {
    C.vscf_chained_public_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *ChainedPublicKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_chained_public_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *ChainedPublicKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_chained_public_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *ChainedPublicKey) Len() uint32 {
    proxyResult := /*pr4*/C.vscf_chained_public_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *ChainedPublicKey) Bitlen() uint32 {
    proxyResult := /*pr4*/C.vscf_chained_public_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *ChainedPublicKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_chained_public_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
