package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles ECC private key.
*/
type EccPrivateKey struct {
    cCtx *C.vscf_ecc_private_key_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *EccPrivateKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewEccPrivateKey() *EccPrivateKey {
    ctx := C.vscf_ecc_private_key_new()
    obj := &EccPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*EccPrivateKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPrivateKeyWithCtx(ctx *C.vscf_ecc_private_key_t /*ct10*/) *EccPrivateKey {
    obj := &EccPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*EccPrivateKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPrivateKeyCopy(ctx *C.vscf_ecc_private_key_t /*ct10*/) *EccPrivateKey {
    obj := &EccPrivateKey {
        cCtx: C.vscf_ecc_private_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*EccPrivateKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *EccPrivateKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *EccPrivateKey) delete() {
    C.vscf_ecc_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *EccPrivateKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *EccPrivateKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4.1 */
}

/*
* Length of the key in bytes.
*/
func (obj *EccPrivateKey) Len() uint {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *EccPrivateKey) Bitlen() uint {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *EccPrivateKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *EccPrivateKey) ExtractPublicKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_extract_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}
