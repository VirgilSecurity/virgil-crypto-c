package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handles interchangeable public key representation.
*/
type RawPublicKey struct {
    IKey
    IPublicKey
    cCtx *C.vscf_raw_public_key_t /*ct10*/
}

/*
* Return key data.
*/
func (this RawPublicKey) Data () []byte {
    proxyResult := /*pr4*/C.vscf_raw_public_key_data(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/* Handle underlying C context. */
func (this RawPublicKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewRawPublicKey () *RawPublicKey {
    ctx := C.vscf_raw_public_key_new()
    return &RawPublicKey {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawPublicKeyWithCtx (ctx *C.vscf_raw_public_key_t /*ct10*/) *RawPublicKey {
    return &RawPublicKey {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawPublicKeyCopy (ctx *C.vscf_raw_public_key_t /*ct10*/) *RawPublicKey {
    return &RawPublicKey {
        cCtx: C.vscf_raw_public_key_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this RawPublicKey) clear () {
    C.vscf_raw_public_key_delete(this.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (this RawPublicKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_raw_public_key_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this RawPublicKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_raw_public_key_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this RawPublicKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_raw_public_key_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (this RawPublicKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_raw_public_key_bitlen(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this RawPublicKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_raw_public_key_is_valid(this.cCtx)

    return bool(proxyResult) /* r9 */
}
