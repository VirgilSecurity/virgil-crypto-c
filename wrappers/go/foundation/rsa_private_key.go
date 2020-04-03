package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles RSA private key.
*/
type RsaPrivateKey struct {
    cCtx *C.vscf_rsa_private_key_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *RsaPrivateKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRsaPrivateKey() *RsaPrivateKey {
    ctx := C.vscf_rsa_private_key_new()
    obj := &RsaPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RsaPrivateKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPrivateKeyWithCtx(ctx *C.vscf_rsa_private_key_t /*ct10*/) *RsaPrivateKey {
    obj := &RsaPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RsaPrivateKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPrivateKeyCopy(ctx *C.vscf_rsa_private_key_t /*ct10*/) *RsaPrivateKey {
    obj := &RsaPrivateKey {
        cCtx: C.vscf_rsa_private_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RsaPrivateKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RsaPrivateKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RsaPrivateKey) delete() {
    C.vscf_rsa_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *RsaPrivateKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *RsaPrivateKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *RsaPrivateKey) Len() uint {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *RsaPrivateKey) Bitlen() uint {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *RsaPrivateKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *RsaPrivateKey) ExtractPublicKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_extract_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4.1 */
}
