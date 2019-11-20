package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Handles RSA public key.
*/
type RsaPublicKey struct {
    cCtx *C.vscf_rsa_public_key_t /*ct10*/
}

/*
* Return public key exponent.
*/
func (obj *RsaPublicKey) KeyExponent() uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_key_exponent(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/* Handle underlying C context. */
func (obj *RsaPublicKey) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRsaPublicKey() *RsaPublicKey {
    ctx := C.vscf_rsa_public_key_new()
    obj := &RsaPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPublicKeyWithCtx(ctx *C.vscf_rsa_public_key_t /*ct10*/) *RsaPublicKey {
    obj := &RsaPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPublicKeyCopy(ctx *C.vscf_rsa_public_key_t /*ct10*/) *RsaPublicKey {
    obj := &RsaPublicKey {
        cCtx: C.vscf_rsa_public_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RsaPublicKey) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.clear()
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

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *RsaPublicKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_alg_info(obj.cCtx)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *RsaPublicKey) Len() uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *RsaPublicKey) Bitlen() uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_bitlen(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *RsaPublicKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_rsa_public_key_is_valid(obj.cCtx)

    return bool(proxyResult) /* r9 */
}
