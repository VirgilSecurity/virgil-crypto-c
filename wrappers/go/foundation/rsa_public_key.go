package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles RSA public key.
*/
type RsaPublicKey struct {
    cCtx *C.vscf_rsa_public_key_t /*ct10*/
}

/*
* Return public key exponent.
*/
func (obj *RsaPublicKey) KeyExponent() uint {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_key_exponent(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/* Handle underlying C context. */
func (obj *RsaPublicKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRsaPublicKey() *RsaPublicKey {
    ctx := C.vscf_rsa_public_key_new()
    obj := &RsaPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RsaPublicKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPublicKeyWithCtx(ctx *C.vscf_rsa_public_key_t /*ct10*/) *RsaPublicKey {
    obj := &RsaPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RsaPublicKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPublicKeyCopy(ctx *C.vscf_rsa_public_key_t /*ct10*/) *RsaPublicKey {
    obj := &RsaPublicKey {
        cCtx: C.vscf_rsa_public_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RsaPublicKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RsaPublicKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RsaPublicKey) delete() {
    C.vscf_rsa_public_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *RsaPublicKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *RsaPublicKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *RsaPublicKey) Len() uint {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *RsaPublicKey) Bitlen() uint {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *RsaPublicKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
