package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handles RSA private key.
*/
type RsaPrivateKey struct {
    IKey
    IPrivateKey
    cCtx *C.vscf_rsa_private_key_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *RsaPrivateKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRsaPrivateKey () *RsaPrivateKey {
    ctx := C.vscf_rsa_private_key_new()
    return &RsaPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPrivateKeyWithCtx (ctx *C.vscf_rsa_private_key_t /*ct10*/) *RsaPrivateKey {
    return &RsaPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPrivateKeyCopy (ctx *C.vscf_rsa_private_key_t /*ct10*/) *RsaPrivateKey {
    return &RsaPrivateKey {
        cCtx: C.vscf_rsa_private_key_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *RsaPrivateKey) Delete () {
    C.vscf_rsa_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *RsaPrivateKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *RsaPrivateKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *RsaPrivateKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *RsaPrivateKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_bitlen(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *RsaPrivateKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_is_valid(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *RsaPrivateKey) ExtractPublicKey () (IPublicKey, error) {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_extract_public_key(obj.cCtx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
