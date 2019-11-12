package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handles ECC private key.
*/
type EccPrivateKey struct {
    IKey
    IPrivateKey
    cCtx *C.vscf_ecc_private_key_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *EccPrivateKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewEccPrivateKey () *EccPrivateKey {
    ctx := C.vscf_ecc_private_key_new()
    return &EccPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPrivateKeyWithCtx (ctx *C.vscf_ecc_private_key_t /*ct10*/) *EccPrivateKey {
    return &EccPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPrivateKeyCopy (ctx *C.vscf_ecc_private_key_t /*ct10*/) *EccPrivateKey {
    return &EccPrivateKey {
        cCtx: C.vscf_ecc_private_key_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *EccPrivateKey) Delete () {
    C.vscf_ecc_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *EccPrivateKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *EccPrivateKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *EccPrivateKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *EccPrivateKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_bitlen(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *EccPrivateKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_is_valid(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *EccPrivateKey) ExtractPublicKey () (IPublicKey, error) {
    proxyResult := /*pr4*/C.vscf_ecc_private_key_extract_public_key(obj.cCtx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
