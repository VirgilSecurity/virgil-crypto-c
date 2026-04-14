package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles ECC public key.
*/
type EccPublicKey struct {
    cCtx *C.vscf_ecc_public_key_t
}

/* Handle underlying C context. */
func (obj *EccPublicKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewEccPublicKey() *EccPublicKey {
    ctx := C.vscf_ecc_public_key_new()
    obj := &EccPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*EccPublicKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPublicKeyWithCtx(ctx *C.vscf_ecc_public_key_t) *EccPublicKey {
    obj := &EccPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*EccPublicKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPublicKeyCopy(ctx *C.vscf_ecc_public_key_t) *EccPublicKey {
    obj := &EccPublicKey {
        cCtx: C.vscf_ecc_public_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*EccPublicKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *EccPublicKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *EccPublicKey) delete() {
    C.vscf_ecc_public_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *EccPublicKey) AlgId() AlgId {
    proxyResult := C.vscf_ecc_public_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *EccPublicKey) AlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_ecc_public_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult)
}

/*
* Length of the key in bytes.
*/
func (obj *EccPublicKey) Len() uint {
    proxyResult := C.vscf_ecc_public_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Length of the key in bits.
*/
func (obj *EccPublicKey) Bitlen() uint {
    proxyResult := C.vscf_ecc_public_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *EccPublicKey) IsValid() bool {
    proxyResult := C.vscf_ecc_public_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult)
}
