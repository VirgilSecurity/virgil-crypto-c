package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handles ECC public key.
*/
type EccPublicKey struct {
    IKey
    IPublicKey
    cCtx *C.vscf_ecc_public_key_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *EccPublicKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewEccPublicKey () *EccPublicKey {
    ctx := C.vscf_ecc_public_key_new()
    return &EccPublicKey {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPublicKeyWithCtx (ctx *C.vscf_ecc_public_key_t /*ct10*/) *EccPublicKey {
    return &EccPublicKey {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccPublicKeyCopy (ctx *C.vscf_ecc_public_key_t /*ct10*/) *EccPublicKey {
    return &EccPublicKey {
        cCtx: C.vscf_ecc_public_key_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *EccPublicKey) Delete () {
    C.vscf_ecc_public_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *EccPublicKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *EccPublicKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *EccPublicKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *EccPublicKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_bitlen(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *EccPublicKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_is_valid(obj.cCtx)

    return bool(proxyResult) /* r9 */
}
