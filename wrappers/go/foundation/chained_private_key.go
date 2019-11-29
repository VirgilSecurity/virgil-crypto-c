package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles chained private key.
*
* Chained private key contains 2 private keys:
* - l1 key:
* - can be used for decryption data decrypted by the l2;
* - can be used to produce l1 signature;
* - l2 key:
* - can be used for decryption data;
* - can be used to produce l1 signature.
*/
type ChainedPrivateKey struct {
    cCtx *C.vscf_chained_private_key_t /*ct10*/
}

/*
* Return l1 private key.
*/
func (obj *ChainedPrivateKey) L1Key() (PrivateKey, error) {
    proxyResult := /*pr4*/C.vscf_chained_private_key_l1_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Return l2 private key.
*/
func (obj *ChainedPrivateKey) L2Key() (PrivateKey, error) {
    proxyResult := /*pr4*/C.vscf_chained_private_key_l2_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *ChainedPrivateKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewChainedPrivateKey() *ChainedPrivateKey {
    ctx := C.vscf_chained_private_key_new()
    obj := &ChainedPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChainedPrivateKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChainedPrivateKeyWithCtx(ctx *C.vscf_chained_private_key_t /*ct10*/) *ChainedPrivateKey {
    obj := &ChainedPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChainedPrivateKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChainedPrivateKeyCopy(ctx *C.vscf_chained_private_key_t /*ct10*/) *ChainedPrivateKey {
    obj := &ChainedPrivateKey {
        cCtx: C.vscf_chained_private_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*ChainedPrivateKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *ChainedPrivateKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *ChainedPrivateKey) delete() {
    C.vscf_chained_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *ChainedPrivateKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_chained_private_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *ChainedPrivateKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_chained_private_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *ChainedPrivateKey) Len() uint32 {
    proxyResult := /*pr4*/C.vscf_chained_private_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *ChainedPrivateKey) Bitlen() uint32 {
    proxyResult := /*pr4*/C.vscf_chained_private_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *ChainedPrivateKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_chained_private_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *ChainedPrivateKey) ExtractPublicKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_chained_private_key_extract_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}
