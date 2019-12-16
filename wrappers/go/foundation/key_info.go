package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


type KeyInfo struct {
    cCtx *C.vscf_key_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyInfo() *KeyInfo {
    ctx := C.vscf_key_info_new()
    obj := &KeyInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyInfoWithCtx(ctx *C.vscf_key_info_t /*ct2*/) *KeyInfo {
    obj := &KeyInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyInfoCopy(ctx *C.vscf_key_info_t /*ct2*/) *KeyInfo {
    obj := &KeyInfo {
        cCtx: C.vscf_key_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KeyInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyInfo) delete() {
    C.vscf_key_info_delete(obj.cCtx)
}

/*
* Build key information based on the generic algorithm information.
*/
func NewKeyInfoWithAlgInfo(algInfo AlgInfo) *KeyInfo {
    proxyResult := /*pr4*/C.vscf_key_info_new_with_alg_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    obj := &KeyInfo {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*KeyInfo).Delete)
    return obj
}

/*
* Return true if a key is a compound key
*/
func (obj *KeyInfo) IsCompound() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_compound(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a chained key
*/
func (obj *KeyInfo) IsChained() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_chained(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key and compounds cipher key
* and signer key are chained keys.
*/
func (obj *KeyInfo) IsCompoundChained() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_compound_chained(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key and compounds cipher key
* is a chained key.
*/
func (obj *KeyInfo) IsCompoundChainedCipher() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_compound_chained_cipher(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key and compounds signer key
* is a chained key.
*/
func (obj *KeyInfo) IsCompoundChainedSigner() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_compound_chained_signer(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key that contains chained keys
* for encryption/decryption and signing/verifying that itself
* contains a combination of classic keys and post-quantum keys.
*/
func (obj *KeyInfo) IsHybridPostQuantum() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_hybrid_post_quantum(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key that contains a chained key
* for encryption/decryption that contains a classic key and
* a post-quantum key.
*/
func (obj *KeyInfo) IsHybridPostQuantumCipher() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_hybrid_post_quantum_cipher(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key that contains a chained key
* for signing/verifying that contains a classic key and
* a post-quantum key.
*/
func (obj *KeyInfo) IsHybridPostQuantumSigner() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_hybrid_post_quantum_signer(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return common type of the key.
*/
func (obj *KeyInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return compound's cipher key id, if key is compound.
* Return None, otherwise.
*/
func (obj *KeyInfo) CompoundCipherAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_cipher_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return compound's signer key id, if key is compound.
* Return None, otherwise.
*/
func (obj *KeyInfo) CompoundSignerAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_signer_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return chained l1 key id, if key is chained.
* Return None, otherwise.
*/
func (obj *KeyInfo) ChainedL1AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_chained_l1_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return chained l2 key id, if key is chained.
* Return None, otherwise.
*/
func (obj *KeyInfo) ChainedL2AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_chained_l2_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return l1 key id of compound's cipher key, if key is compound(chained, ...)
* Return None, otherwise.
*/
func (obj *KeyInfo) CompoundCipherL1AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_cipher_l1_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return l2 key id of compound's cipher key, if key is compound(chained, ...)
* Return None, otherwise.
*/
func (obj *KeyInfo) CompoundCipherL2AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_cipher_l2_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return l1 key id of compound's signer key, if key is compound(..., chained)
* Return None, otherwise.
*/
func (obj *KeyInfo) CompoundSignerL1AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_signer_l1_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return l2 key id of compound's signer key, if key is compound(..., chained)
* Return None, otherwise.
*/
func (obj *KeyInfo) CompoundSignerL2AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_signer_l2_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
