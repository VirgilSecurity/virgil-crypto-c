package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
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
func (this EccPublicKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
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

/// Release underlying C context.
func (this EccPublicKey) clear () {
    C.vscf_ecc_public_key_delete(this.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (this EccPublicKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this EccPublicKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this EccPublicKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (this EccPublicKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_bitlen(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this EccPublicKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_ecc_public_key_is_valid(this.cCtx)

    return bool(proxyResult) /* r9 */
}
