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
* Return true if a key is a hybrid key
*/
func (obj *KeyInfo) IsHybrid() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_hybrid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key and compounds cipher key
* and signer key are hybrid keys.
*/
func (obj *KeyInfo) IsCompoundHybrid() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_compound_hybrid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key and compounds cipher key
* is a hybrid key.
*/
func (obj *KeyInfo) IsCompoundHybridCipher() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_compound_hybrid_cipher(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key and compounds signer key
* is a hybrid key.
*/
func (obj *KeyInfo) IsCompoundHybridSigner() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_compound_hybrid_signer(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key that contains hybrid keys
* for encryption/decryption and signing/verifying that itself
* contains a combination of classic keys and post-quantum keys.
*/
func (obj *KeyInfo) IsHybridPostQuantum() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_hybrid_post_quantum(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key that contains a hybrid key
* for encryption/decryption that contains a classic key and
* a post-quantum key.
*/
func (obj *KeyInfo) IsHybridPostQuantumCipher() bool {
    proxyResult := /*pr4*/C.vscf_key_info_is_hybrid_post_quantum_cipher(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if a key is a compound key that contains a hybrid key
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
* Return hybrid's first key id, if key is hybrid.
* Return None, otherwise.
*/
func (obj *KeyInfo) HybridFirstKeyAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_hybrid_first_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return hybrid's second key id, if key is hybrid.
* Return None, otherwise.
*/
func (obj *KeyInfo) HybridSecondKeyAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_hybrid_second_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return hybrid's first key id of compound's cipher key,
* if key is compound(hybrid, ...), None - otherwise.
*/
func (obj *KeyInfo) CompoundHybridCipherFirstKeyAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_hybrid_cipher_first_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return hybrid's second key id of compound's cipher key,
* if key is compound(hybrid, ...), None - otherwise.
*/
func (obj *KeyInfo) CompoundHybridCipherSecondKeyAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_hybrid_cipher_second_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return hybrid's first key id of compound's signer key,
* if key is compound(..., hybrid), None - otherwise.
*/
func (obj *KeyInfo) CompoundHybridSignerFirstKeyAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_hybrid_signer_first_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return hybrid's second key id of compound's signer key,
* if key is compound(..., hybrid), None - otherwise.
*/
func (obj *KeyInfo) CompoundHybridSignerSecondKeyAlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_key_info_compound_hybrid_signer_second_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
